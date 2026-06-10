"""Parse raw detection_logic text into structured, human-readable sections."""

import re


def parse_detection_logic(text: str | None) -> list[dict]:
    """Parse detection logic text into a list of structured check steps.

    Each step contains:
      - title: what was checked
      - check_type: existence / inventory / version / unknown
      - required: condition requirement string
      - results: list of result strings
      - evidence: list of evidence strings
    """
    if not text or text in ("", "N/A", "None"):
        return []

    # Remove the trailing metadata explanation (after 🔎)
    note = ""
    note_match = re.search(r"🔎\s*(.+?)$", text)
    if note_match:
        note = note_match.group(1).strip()
        text = text[: note_match.start()].strip()

    # Split by ▶ to get individual check steps
    # Handle both "▶ " and "▶" (no space)
    chunks = re.split(r"▶\s*", text)
    steps = []

    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue

        step = _parse_single_check(chunk)
        if step:
            steps.append(step)

    # Attach note to last step
    if steps and note:
        steps[-1]["note"] = note

    return steps


def _parse_single_check(chunk: str) -> dict | None:
    """Parse a single check step from text chunk."""
    result = {
        "title": "",
        "check_type": "unknown",
        "required": "",
        "results": [],
        "evidence": [],
        "note": "",
    }

    # Extract title: everything before known keywords
    # Known patterns: "No comparisons available", "Required:", "Found on asset:", "Evidence"
    title_match = re.match(
        r"^(.*?)(?:No comparisons available|Required:|Found on asset:|Evidence|inventory)",
        chunk,
        re.DOTALL,
    )
    if title_match:
        result["title"] = title_match.group(1).strip()
    else:
        # Fallback: use first 120 chars
        result["title"] = chunk[:120].strip()

    # Clean up title: remove trailing parenthetical check details
    result["title"] = re.sub(r"\([^)]*(?:less than|greater than|equals|matches)[^)]*\)\s*$", "", result["title"]).strip()

    # Detect check type
    if re.search(r"No comparisons available\s*:\s*Existence check", chunk):
        result["check_type"] = "existence"
    elif re.search(r"inventory", chunk, re.IGNORECASE) and "Evidence" in chunk:
        result["check_type"] = "inventory"
    elif re.search(r"less than|greater than|equals|matches", chunk):
        result["check_type"] = "version"

    # Extract Required condition
    req_match = re.search(r"Required:\s*(.*?)(?=Found on asset:|Evidence|$)", chunk, re.DOTALL)
    if req_match:
        result["required"] = req_match.group(1).strip()

    # Extract "Found on asset" results
    found_section = re.search(r"Found on asset:\s*(.*?)(?=Evidence|$)", chunk, re.DOTALL)
    if found_section:
        items = re.findall(r"•\s*(.+?)(?=•|$)", found_section.group(1), re.DOTALL)
        result["results"] = [item.strip() for item in items if item.strip()]

    # If no "Found on asset" but has "Item was found"
    if not result["results"] and "Item was found" in chunk:
        result["results"] = ["Item was found"]

    # Extract Evidence
    evidence_section = re.search(r"Evidence\s*(?:\(registry / file\))?\s*:\s*(.*?)(?=🔎|$)", chunk, re.DOTALL)
    if evidence_section:
        items = re.findall(r"•\s*(.+?)(?=•|$)", evidence_section.group(1), re.DOTALL)
        result["evidence"] = [item.strip() for item in items if item.strip()]

    # Only return if we have something meaningful
    if result["title"] or result["results"] or result["evidence"]:
        return result
    return None
