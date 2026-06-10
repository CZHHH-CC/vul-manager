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
