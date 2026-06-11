"""Parse raw detection_logic text to extract detected items (version + path)."""

import re


def parse_detection_logic(text: str | None) -> list[dict]:
    """Extract detected items from detection logic text.

    Returns a flat list of detected items, each with:
      - name: package/software name
      - version: detected version string (if available)
      - path: file/registry/package path (if available)
    """
    if not text or text in ("", "N/A", "None"):
        return []

    # Remove metadata after 🔎
    text = re.split(r"🔎", text)[0].strip()

    # Normalize: split concatenated keywords so regex can match
    text = re.sub(r"(inventory)(Evidence)", r"\1 \2", text)
    text = re.sub(r"(vulnerability)(Evidence)", r"\1 \2", text)
    text = re.sub(r"(Evidence)(file_item|registry_item)", r"\1 \2", text)
    text = re.sub(r"(registry_item)([A-Z])", r"\1 \2", text)
    text = re.sub(r"(\d+\.?\d*)(vulnerability|Evidence|Checks|Required|Found)", r"\1 \2", text)
    text = re.sub(r"(filepath:\s*[^\s])(Evidence|✓|▶)", r"\1 \2", text)

    # Split by ▶ to process each check step separately
    chunks = re.split(r"▶\s*", text)

    items = []
    seen = set()

    def _add(name="", version="", path=""):
        name = name.strip().strip("the ")
        version = version.strip()
        path = path.strip()
        version = re.sub(r"^\d+:", "", version)
        key = f"{name}|{version}|{path}"
        if key not in seen and (name or version or path):
            seen.add(key)
            items.append({"name": name, "version": version, "path": path})

    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue

        # filepath
        for m in re.finditer(r"filepath:\s*(.+?)(?=✓|▶|$)", chunk):
            _add(path=m.group(1).strip())

        # version: X.X.X (stop at keywords)
        for m in re.finditer(r"version:\s*([\d][\d\.\-\w]*?)(?:\s*(?:Evidence|Checks|Required|Found|✓|▶)|$)", chunk):
            _add(version=m.group(1))

        # package: xxx
        for m in re.finditer(r"package:\s*(.+?)(?=✓|▶|$)", chunk):
            pkg = m.group(1).strip()
            if pkg:
                name, version = _split_package_version(pkg)
                _add(name=name, version=version, path=pkg)

        # registry_item KEY\PATH
        for m in re.finditer(r"registry_item\s+([A-Z_]+\\[^\s✓▶]+)", chunk):
            reg = m.group(1).strip()
            if len(reg) > 3:
                _add(path=reg)

        # name:: arch: xxx, evr: version
        for m in re.finditer(r"([\w\-\.]+)::\s*arch:\s*[\w_]+,\s*evr:\s*([\d:\.\-\w]+)", chunk):
            _add(name=m.group(1), version=m.group(2))

        # value: [version]
        for m in re.finditer(r"value:\s*\[([^\]]*)\]", chunk):
            _add(version=m.group(1))

        # "version of X is less than Y"
        ver_match = re.search(r"version of\s+(.+?)\s+is\s+(?:less than|greater than)\s+([\d:\.\-\w]+?)(?:\s*(?:Evidence|Checks|Required|Found|✓|▶)|$)", chunk)
        if ver_match:
            _add(name=ver_match.group(1).strip(), version=ver_match.group(2))

        # "Check if X is installed" + found
        if "Item was found" in chunk or "✓ true" in chunk:
            inst_match = re.search(r"Check if\s+(?:the\s+)?(.+?)\s+is\s+installed", chunk)
            if inst_match:
                name = inst_match.group(1).strip()
                name = re.sub(r"\s*\(.*?\)\s*", "", name)
                if name and len(name) > 2 and not any(i["name"] == name for i in items):
                    _add(name=name)

    # Post-process: deduplicate by name, keep entries with most info
    return _dedupe_items(items)


def extract_fix_threshold(text: str | None) -> str | None:
    """Extract the scanner's fix threshold version from detection logic.

    CrowdStrike checks like "version ... is less than 1.6.00.26474" encode the
    authoritative fixed version: upgrading to >= that version remediates the CVE.
    Returns the highest such threshold, or None.
    """
    if not text:
        return None
    cands = re.findall(r"less than\s+([0-9][0-9A-Za-z.\-_:]*)", text, re.IGNORECASE)
    cands = [c.strip().rstrip(".") for c in cands if re.search(r"\d", c)]
    if not cands:
        return None
    cands.sort(key=lambda s: [int(x) for x in re.findall(r"\d+", s)])
    return cands[-1]


def version_tuple(s: str) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", str(s or ""))]


def version_lt(a: str, b: str) -> bool:
    """Numeric version comparison: is a < b? (handles 1.6.00.x == 1.6.0.x)."""
    return version_tuple(a) < version_tuple(b)


def _norm_name(s: str) -> str:
    return re.sub(r"[\s\-_]+", "", (s or "").lower())


def _ver_core(s: str) -> str:
    """Extract the dotted numeric core of a version string."""
    m = re.search(r"\d+(?:\.\d+)+", str(s or ""))
    if m:
        return m.group(0)
    return re.sub(r"[^\d.]", "", str(s or ""))


def cross_validate_components(ai_components: list[dict] | None,
                             regex_components: list[dict] | None):
    """Cross-check AI-extracted components against regex-extracted ones.

    Returns (display_list, summary):
      - display_list: unified rows, each with name/version/path + source + check
        check in {"一致","版本差异","仅AI","仅正则",""}
      - summary: {available, verdict, agree, diff, ai_only, regex_only, source}
    """
    ai = ai_components or []
    regex = regex_components or []

    # Only one source available -> nothing to cross-check
    if not ai or not regex:
        src = "ai" if ai else ("regex" if regex else None)
        rows = [{**c, "source": src, "check": ""} for c in (ai or regex)]
        verdict = "仅AI来源" if ai else ("仅正则来源" if regex else "无数据")
        return rows, {"available": False, "verdict": verdict, "source": src,
                      "agree": 0, "diff": 0, "ai_only": 0, "regex_only": 0}

    used = set()
    rows = []
    agree = diff = ai_only = 0

    for a in ai:
        an, av = _norm_name(a.get("name")), _ver_core(a.get("version"))
        match_idx = None
        for i, r in enumerate(regex):
            if i in used:
                continue
            rn, rv = _norm_name(r.get("name")), _ver_core(r.get("version"))
            name_match = an and rn and (an in rn or rn in an)
            ver_match = av and rv and (av in rv or rv in av)
            path_match = a.get("path") and r.get("path") and (
                _norm_name(a["path"]) in _norm_name(r["path"]) or _norm_name(r["path"]) in _norm_name(a["path"]))
            if name_match or path_match or (not an and ver_match):
                match_idx = i
                break

        row = {"name": a.get("name"), "version": a.get("version"),
               "path": a.get("path"), "source": "ai"}
        if match_idx is not None:
            used.add(match_idx)
            rv = _ver_core(regex[match_idx].get("version"))
            row["source"] = "both"
            if av and rv and not (av in rv or rv in av):
                row["check"] = "版本差异"
                row["regex_version"] = regex[match_idx].get("version")
                diff += 1
            else:
                row["check"] = "一致"
                agree += 1
        else:
            row["check"] = "仅AI"
            ai_only += 1
        rows.append(row)

    regex_only_items = [r for i, r in enumerate(regex) if i not in used]
    for r in regex_only_items:
        rows.append({"name": r.get("name"), "version": r.get("version"),
                     "path": r.get("path"), "source": "regex", "check": "仅正则"})

    regex_only = len(regex_only_items)
    verdict = "一致" if (diff == 0 and ai_only == 0 and regex_only == 0) else "有差异"
    return rows, {"available": True, "verdict": verdict, "source": "both",
                  "agree": agree, "diff": diff, "ai_only": ai_only, "regex_only": regex_only}


def _split_package_version(pkg: str) -> tuple[str, str]:
    """Split a package string like 'kernel-5.14.0-611.45.1.el9_7.x86_64' into name and version."""
    # Common patterns: name-version.arch.rpm or name-version
    m = re.match(r"^([\w\-\.]+?)[\-](\d[\d:\.\-\w]+?)(?:\.(?:x86_64|amd64|noarch|i386|i686|aarch64|ppc64le|s390x|src))?(?:\.rpm)?$", pkg)
    if m:
        return m.group(1), m.group(2)
    return pkg, ""


def _dedupe_items(items: list[dict]) -> list[dict]:
    """Remove duplicate items, keeping the one with most information."""
    # Filter out noise names
    noise = {"source linux-signed", "source linux", "source linux-lowlatency"}
    items = [i for i in items if i["name"].lower() not in noise]

    # Group named items: if one name is a prefix of another, keep the longer one
    named = [i for i in items if i["name"]]
    path_only = [i for i in items if not i["name"]]

    # Sort by name length descending so longer names come first
    named.sort(key=lambda x: len(x["name"]), reverse=True)

    kept = []
    for item in named:
        # Check if this name is already covered by a longer name
        norm = re.sub(r"[\s\-_]+", "", item["name"].lower())
        already_covered = False
        for existing in kept:
            existing_norm = re.sub(r"[\s\-_]+", "", existing["name"].lower())
            if norm in existing_norm or existing_norm in norm:
                # Keep the one with more info
                if (bool(item["version"]) > bool(existing["version"]) or
                    (bool(item["version"]) == bool(existing["version"]) and bool(item["path"]) > bool(existing["path"]))):
                    kept.remove(existing)
                else:
                    already_covered = True
                break
        if not already_covered:
            kept.append(item)

    return kept + path_only
