"""Parse ServiceNow Work notes into scanner retest events."""

import hashlib
import re
from datetime import datetime


ENTRY_HEADER = re.compile(
    r"(?<!\d)(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+-\s+(.{1,200}?)\s+\(Work notes\)\s*",
    re.IGNORECASE,
)


def _clean(value: str | None) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _component_name(context: str) -> str:
    patterns = [
        r"version of\s+(.+?)\s+is\s+(?:less|greater|equal)",
        r"version of\s+(.+?)\s+Checks\s*:",
        r"Check if\s+(?:source\s+)?(.+?)\s+is installed",
    ]
    for pattern in patterns:
        match = re.search(pattern, context, re.IGNORECASE)
        if match:
            return _clean(match.group(1))
    return ""


def _package_parts(package: str) -> tuple[str, str]:
    package = _clean(package)
    match = re.match(r"(.+?)-(\d[0-9A-Za-z.+:~_-]*)(?:\.(?:amd64|x86_64|i[3-6]86|noarch))?$", package)
    if not match:
        return package, ""
    return match.group(1), match.group(2)


def parse_retest_components(detection_text: str | None) -> list[dict]:
    """Extract component, detected version and path from one retest note."""
    if not detection_text:
        return []

    items = []
    seen = set()

    def add(name: str = "", version: str = "", path: str = "") -> None:
        item = {
            "name": _clean(name),
            "version": _clean(version).strip("[]"),
            "path": _clean(path),
        }
        key = (item["name"].lower(), item["version"], item["path"].lower())
        if key not in seen and any(item.values()):
            seen.add(key)
            items.append(item)

    # Some scanner notes use a concise one-line result instead of full logic.
    simple = re.search(
        r"(.+?)\s+v([0-9][0-9A-Za-z.+:~_-]*)\s+at\s+(.+?)\s+is still detected",
        detection_text,
        re.IGNORECASE | re.DOTALL,
    )
    if simple:
        add(simple.group(1), simple.group(2), simple.group(3))

    # Full CrowdStrike logic contains one or more Found/Evidence pairs.
    pair_pattern = re.compile(
        r"Found\s*:\s*(.*?)\s+Evidence\s*:\s*(.*?)(?=\s+Vendor Advisory:|\s+▶|\Z)",
        re.IGNORECASE | re.DOTALL,
    )
    for pair in pair_pattern.finditer(detection_text):
        found, evidence = pair.group(1), pair.group(2)
        context = detection_text[max(0, pair.start() - 700):pair.start()]
        name = _component_name(context)

        combined = re.findall(
            r"captured_content:\s*\[?([^\],\r\n]+)\]?,\s*file_system_path:\s*([^\r\n]+)",
            found,
            re.IGNORECASE,
        )
        for version, path in combined:
            add(name, version, path)

        if not combined:
            display_versions = re.findall(
                r"\bDisplayVersion\s*::?\s*value\s*:\s*\[?([^\],\r\n]+)",
                found,
                re.IGNORECASE,
            )
            versions = display_versions or re.findall(
                r"(?<![A-Za-z])(?:product_)?version\s*:\s*([^,\r\n]+)",
                found,
                re.IGNORECASE,
            )
            paths = re.findall(
                r"(?:filepath|zipfile Path):\s*(.*?)(?=\s+-\s+(?:filepath|zipfile Path):|\r?\n|$)",
                evidence,
                re.IGNORECASE,
            )
            paths.extend(re.findall(
                r"registry\s*:\s*([^\r\n]+)", evidence, re.IGNORECASE
            ))

            if versions or paths:
                count = max(len(versions), len(paths))
                for index in range(count):
                    version = versions[index] if index < len(versions) else (versions[0] if len(versions) == 1 else "")
                    path = paths[index] if index < len(paths) else ""
                    add(name, version, path)

        for package in re.findall(r"package:\s*([^\r\n]+)", evidence, re.IGNORECASE):
            package_name, version = _package_parts(package)
            add(name or package_name, version, package)

        for registry in re.findall(r"registry_item\s+([^\r\n]+)", evidence, re.IGNORECASE):
            add(name, "", registry)

    return items


def parse_work_notes(work_notes: str | None) -> list[dict]:
    """Return automated scanner review events from a ServiceNow Work notes cell."""
    if not work_notes or str(work_notes).lower() in {"nan", "none"}:
        return []

    text = str(work_notes)
    headers = list(ENTRY_HEADER.finditer(text))
    events = []

    for index, header in enumerate(headers):
        body_end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        body = text[header.end():body_end].strip()
        actor = _clean(header.group(2))
        if "Integration ServiceNow" not in actor:
            continue
        if not re.search(r"automatically reviewed|automatically closed|Crowdstrike status", body, re.I):
            continue

        status_match = re.search(r"Crowdstrike status:\s*([A-Za-z ]+?)(?:\s*\(|\.)", body, re.I)
        state_match = re.search(r"Status changed from\s+(.+?)\s+to\s+(.+?)\.", body, re.I)
        previous_state = _clean(state_match.group(1)) if state_match else ""
        new_state = _clean(state_match.group(2)) if state_match else ""
        scanner_status = _clean(status_match.group(1)).lower() if status_match else ""

        reason_match = re.search(r"Reopened because\s+(.+)", body, re.I | re.DOTALL)
        detection_logic = reason_match.group(1).strip() if reason_match else ""
        detection_logic = re.split(r"\s+Vendor Advisory:", detection_logic, maxsplit=1, flags=re.I)[0].strip()

        if reason_match or new_state.lower() == "open":
            result = "reopened"
            summary = "复测仍检出漏洞，工单重新打开"
        elif "automatically closed" in body.lower() or scanner_status == "closed":
            result = "closed"
            summary = "复测未再检出漏洞，工单自动关闭"
        elif scanner_status == "open":
            result = "open"
            summary = "复测仍检出漏洞"
        else:
            result = "reviewed"
            summary = "已完成自动复测"

        retested_at = datetime.strptime(header.group(1), "%Y-%m-%d %H:%M:%S")
        fingerprint_source = f"{header.group(1)}\n{actor}\n{body}"
        events.append({
            "event_key": hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest(),
            "retested_at": retested_at,
            "source": actor,
            "scanner_status": scanner_status,
            "previous_state": previous_state,
            "new_state": new_state,
            "result": result,
            "summary": summary,
            "detection_logic": detection_logic or None,
            "detected_components": parse_retest_components(detection_logic),
            "raw_note": body,
        })

    return events
