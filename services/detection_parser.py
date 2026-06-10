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

    items = []
    seen = set()

    # Extract from "Found on asset" section: "name:: arch: xxx, evr: version"
    for m in re.finditer(r"•\s*([\w\-\.]+)::\s*arch:\s*[\w_]+,\s*evr:\s*([\d:\.\-\w]+)", text):
        name, version = m.group(1), m.group(2)
        # Clean version: remove epoch prefix like "0:"
        version = re.sub(r"^\d+:", "", version)
        key = f"{name}@{version}"
        if key not in seen:
            seen.add(key)
            items.append({"name": name, "version": version, "path": ""})

    # Extract from "Found on asset" section: "value: [version]"
    for m in re.finditer(r"•\s*value:\s*\[([^\]]*)\]", text):
        val = m.group(1).strip()
        if val and val not in seen:
            seen.add(val)
            items.append({"name": "", "version": val, "path": ""})

    # Extract from "Evidence" section: "package: name-version.arch.ext"
    for m in re.finditer(r"•\s*package:\s*(.+?)(?=•|$)", text):
        pkg = m.group(1).strip()
        if pkg and pkg not in seen:
            seen.add(pkg)
            # Try to split package name and version
            name, version = _split_package_version(pkg)
            items.append({"name": name, "version": version, "path": pkg})

    # Extract from "Evidence" section: "filepath: /path/to/file"
    for m in re.finditer(r"•\s*filepath:\s*(.+?)(?=•|$)", text):
        path = m.group(1).strip()
        if path and path not in seen:
            seen.add(path)
            items.append({"name": "", "version": "", "path": path})

    # Extract from "Evidence" section: "registry_item: KEY\PATH"
    for m in re.finditer(r"•\s*registry_item?\s*(?:KEY)?\s*:?\s*(.+?)(?=•|$)", text, re.IGNORECASE):
        reg = m.group(1).strip()
        if reg and reg not in seen and len(reg) > 3:
            seen.add(reg)
            items.append({"name": "", "version": "", "path": reg})

    # Extract version from title: "Check if version of X is less than Y"
    title_ver = re.search(r"version of\s+([\w\-\.]+)\s+is\s+(?:less than|greater than)\s+([\d:\.\-\w]+)", text)
    if title_ver:
        target_name = title_ver.group(1)
        target_ver = re.sub(r"^\d+:", "", title_ver.group(2))
        # Add as meta item if not already captured
        if not any(i["name"] == target_name for i in items):
            items.insert(0, {"name": target_name, "version": target_ver, "path": "", "is_target": True})

    # Extract existence: "Check if X is installed" + "Item was found"
    if "Item was found" in text:
        exist_match = re.search(r"Check if\s+(.+?)\s+is\s+installed", text)
        if exist_match:
            name = exist_match.group(1).strip()
            # Clean up name: remove parenthetical details
            name = re.sub(r"\s*\(.*?\)\s*", "", name).strip()
            if name and not any(i["name"] == name for i in items):
                items.append({"name": name, "version": "", "path": ""})

    return items


def _split_package_version(pkg: str) -> tuple[str, str]:
    """Split a package string like 'kernel-5.14.0-611.45.1.el9_7.x86_64' into name and version."""
    # Common patterns: name-version.arch.rpm or name-version
    m = re.match(r"^([\w\-\.]+?)[\-](\d[\d:\.\-\w]+?)(?:\.(?:x86_64|amd64|noarch|i386|i686|aarch64|ppc64le|s390x|src))?(?:\.rpm)?$", pkg)
    if m:
        return m.group(1), m.group(2)
    return pkg, ""
