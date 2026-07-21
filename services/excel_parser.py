import json
import re
from datetime import datetime
from typing import Optional
import pandas as pd
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session
from db.models import Vulnerability, VulnAnalysis, VulnHistory, VulnRetest, UploadLog
from services.retest_parser import parse_work_notes


def parse_cvss_from_html(soup: BeautifulSoup) -> dict:
    """Extract CVSS-related fields from Description HTML."""
    result = {
        "cvss_score": None,
        "cvss_vector": None,
        "attack_vector": None,
        "attack_complexity": None,
        "privileges_required": None,
        "user_interaction": None,
        "exploit_status": None,
    }

    # CVSS Base Score - find div with text "CVSS Base Score", get next sibling div
    for div in soup.find_all("div"):
        if div.get_text(strip=True) == "CVSS Base Score":
            parent = div.find_parent("td")
            if parent:
                value_div = div.find_next_sibling("div")
                if value_div:
                    score_text = value_div.get_text(strip=True)
                    try:
                        result["cvss_score"] = float(score_text)
                    except (ValueError, TypeError):
                        pass
            break

    # CVSS Vector (e.g., CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
    # Can be in span or div
    for tag in soup.find_all(["span", "div"]):
        text = tag.get_text(strip=True)
        match = re.match(r"(CVSS:\d+\.\d+/[A-Z:/]+)", text)
        if match:
            result["cvss_vector"] = match.group(1)
            break

    # Attack Vector / Complexity / Privileges / User Interaction
    vector_fields = {
        "Attack Vector": "attack_vector",
        "Attack Complexity": "attack_complexity",
        "Privileges Required": "privileges_required",
        "User Interaction": "user_interaction",
    }
    for span in soup.find_all("span"):
        text = span.get_text(strip=True)
        if text in vector_fields:
            sibling = span.find_next_sibling("span")
            if sibling:
                result[vector_fields[text]] = sibling.get_text(strip=True)

    # Exploit status - look for "Exploit status:" in bold text
    for strong in soup.find_all("strong"):
        text = strong.get_text(strip=True)
        if "Exploit status" in text:
            # Get the parent element and extract just the value after the label
            parent = strong.parent
            if parent:
                # The value is typically right after the bold label
                full_text = parent.get_text(strip=True)
                # Try to get just the status value (e.g., "weaponized, poc" or "Actively used")
                match = re.search(r"Exploit status[:\s]+([A-Za-z\s,]+?)(?:Exploit|$)", full_text)
                if match:
                    status = match.group(1).strip().rstrip(",").strip()
                    if status:
                        result["exploit_status"] = status
                        break

    # Fallback: look for Exploitation Status in Threat Intelligence section
    if not result["exploit_status"]:
        for strong in soup.find_all("strong"):
            text = strong.get_text(strip=True)
            if "Exploitation Status" in text:
                parent = strong.parent
                if parent:
                    full_text = parent.get_text(strip=True)
                    match = re.search(r"Exploitation Status[:\s]+([A-Za-z\s,]+?)(?:$)", full_text)
                    if match:
                        result["exploit_status"] = match.group(1).strip()
                        break

    return result


def parse_host_info(soup: BeautifulSoup) -> dict:
    """Extract hostname, IP, and other host info from Description HTML."""
    result = {"ip_address": None, "hostname": None}

    for div in soup.find_all("div"):
        text = div.get_text(strip=True)
        if text == "IP Address":
            parent = div.find_parent("td")
            if parent:
                value_div = div.find_next_sibling("div")
                if value_div:
                    ip = value_div.get_text(strip=True)
                    if ip and ip != "N/A":
                        result["ip_address"] = ip
        elif text == "Hostname":
            parent = div.find_parent("td")
            if parent:
                value_div = div.find_next_sibling("div")
                if value_div:
                    result["hostname"] = value_div.get_text(strip=True)

    return result


def parse_affected_products(soup: BeautifulSoup) -> Optional[str]:
    """Extract affected products list from Description HTML."""
    products = []
    skip_keywords = {"mitigations", "review", "recommended", "remediation"}

    for div in soup.find_all("div"):
        text = div.get_text(strip=True)
        if text in ("Affected Products", "Affected Software / Products"):
            parent = div.find_parent("td")
            if parent:
                content_div = div.find_next_sibling("div")
                if content_div:
                    for span in content_div.find_all("span"):
                        product = span.get_text(strip=True)
                        if product and product.lower() not in skip_keywords:
                            products.append(product)
            break
    return "\n".join(products) if products else None


def parse_remediation(rec_html: str) -> dict:
    """Extract remediation steps and detection logic from Recommendation HTML."""
    result = {"remediation_steps": None, "detection_logic": None}

    if not rec_html or pd.isna(rec_html):
        return result

    soup = BeautifulSoup(str(rec_html), "lxml")

    # Recommended Remediation
    for div in soup.find_all("div"):
        text = div.get_text(strip=True)
        if "Recommended Remediation" in text:
            parent = div.find_parent("td")
            if parent:
                content_div = div.find_next_sibling("div")
                if content_div:
                    result["remediation_steps"] = content_div.get_text(strip=True)
            break

    # Detection Logic
    for div in soup.find_all("div"):
        text = div.get_text(strip=True)
        if "Detection Logic" in text:
            parent = div.find_parent("td")
            if parent:
                content_div = div.find_next_sibling("div")
                if content_div:
                    result["detection_logic"] = content_div.get_text(strip=True)
            break

    return result


def extract_detection_logic(html: str) -> str | None:
    """Extract the 'Detection Logic' block from any HTML column.

    Some tickets put Detection Logic in the Recommendation column, others in
    Description. Tries the structured sibling-div first, then falls back to
    grabbing the text after the 'Detection Logic' marker.
    """
    if not html or pd.isna(html):
        return None
    soup = BeautifulSoup(str(html), "lxml")

    # Structured: a div labelled "Detection Logic" followed by a content div
    for div in soup.find_all("div"):
        if "Detection Logic" in div.get_text(strip=True):
            sib = div.find_next_sibling("div")
            if sib:
                t = sib.get_text(strip=True)
                if t:
                    return t
            break

    # Fallback 1: take the text following the "Detection Logic" marker
    text = soup.get_text(" ", strip=True)
    idx = text.find("Detection Logic")
    if idx >= 0:
        chunk = text[idx:idx + 2500].strip()
        return chunk or None

    # Fallback 2: no "Detection Logic" header, but the evidence block is present
    # (CrowdStrike Spotlight checks). Anchor on the evidence itself.
    for anchor in ["Title: Check if", "filepath:", "package:", "registry_item"]:
        j = text.find(anchor)
        if j >= 0:
            return text[j:j + 2500].strip() or None
    return None


def parse_description(desc_html: str) -> dict:
    """Parse all structured data from Description HTML."""
    if not desc_html or pd.isna(desc_html):
        return {}

    soup = BeautifulSoup(str(desc_html), "lxml")

    cvss_data = parse_cvss_from_html(soup)
    host_data = parse_host_info(soup)
    affected = parse_affected_products(soup)

    return {**cvss_data, **host_data, "affected_products": affected}


def extract_severity_level(severity_str: str) -> int:
    """Convert severity string to numeric level."""
    if not severity_str:
        return 4
    s = str(severity_str).lower()
    if "critical" in s or s.startswith("1"):
        return 1
    elif "high" in s or s.startswith("2"):
        return 2
    elif "medium" in s or s.startswith("3"):
        return 3
    elif "low" in s or s.startswith("4"):
        return 4
    return 4


def parse_excel_to_records(filepath: str) -> list[dict]:
    """Parse Excel file and return list of structured records."""
    df = pd.read_excel(filepath, sheet_name=0)
    records = []

    for _, row in df.iterrows():
        vit_number = str(row.get("Number", "")).strip()
        if not vit_number:
            continue

        desc_html = str(row.get("Description", ""))
        rec_html = str(row.get("Recommendation", ""))

        # Parse HTML fields
        desc_data = parse_description(desc_html)
        rec_data = parse_remediation(rec_html)

        # Detection Logic may live in either column — fall back to Description
        detection_logic = rec_data.get("detection_logic") or extract_detection_logic(desc_html)

        # Parse dates
        opened_at = row.get("Opened")
        updated_at = row.get("Updated")
        if pd.notna(opened_at):
            opened_at = pd.to_datetime(opened_at)
        else:
            opened_at = None
        if pd.notna(updated_at):
            updated_at = pd.to_datetime(updated_at)
        else:
            updated_at = None

        # CVE: prefer the Vulnerability column; fall back to short_description
        cve_id = str(row.get("Vulnerability", "")).strip()
        short_desc = str(row.get("Short description", "")).strip()
        if not cve_id or cve_id.lower() == "nan":
            m = re.search(r"CVE-\d{4}-\d{4,7}", short_desc, re.I)
            cve_id = m.group(0).upper() if m else (cve_id if cve_id.lower() != "nan" else "")

        record = {
            "vit_number": vit_number,
            "cve_id": cve_id,
            "hostname": str(row.get("CI Name / Application Service", "")).strip(),
            "ip_address": desc_data.get("ip_address"),
            "server_class": str(row.get("Class", "")).strip(),
            "severity": str(row.get("Vulnerability Severity", "")).strip(),
            "severity_level": extract_severity_level(str(row.get("Vulnerability Severity", ""))),
            "state": str(row.get("State", "Open")).strip(),
            "short_description": str(row.get("Short description", "")).strip(),
            "assignment_group": str(row.get("Assignment group", "")).strip(),
            "opened_at": opened_at,
            "updated_at": updated_at,
            "raw_description": desc_html,
            "raw_recommendation": rec_html,
            "work_notes": str(row.get("Work notes", "")),
            # Extracted analysis fields
            "cvss_score": desc_data.get("cvss_score"),
            "cvss_vector": desc_data.get("cvss_vector"),
            "attack_vector": desc_data.get("attack_vector"),
            "attack_complexity": desc_data.get("attack_complexity"),
            "privileges_required": desc_data.get("privileges_required"),
            "user_interaction": desc_data.get("user_interaction"),
            "affected_products": desc_data.get("affected_products"),
            "exploit_status": desc_data.get("exploit_status"),
            "remediation_steps": rec_data.get("remediation_steps"),
            "detection_logic": detection_logic,
        }
        records.append(record)

    return records


def upsert_vulnerabilities(
    db: Session,
    records: list[dict],
    *,
    commit: bool = True,
) -> dict:
    """Insert or update vulnerabilities. Returns counts."""
    new_count = 0
    updated_count = 0
    error_count = 0
    retest_count = 0

    def sync_retests(vulnerability: Vulnerability, work_notes: str | None) -> int:
        imported = 0
        existing = {
            item.event_key: item
            for item in db.query(VulnRetest).filter(
                VulnRetest.vulnerability_id == vulnerability.id
            ).all()
        }
        for event in parse_work_notes(work_notes):
            values = {
                **event,
                "detected_components": json.dumps(
                    event["detected_components"], ensure_ascii=False
                ),
            }
            current = existing.get(event["event_key"])
            if current:
                for field, value in values.items():
                    setattr(current, field, value)
                continue
            db.add(VulnRetest(vulnerability_id=vulnerability.id, **values))
            imported += 1
        return imported

    for record in records:
        try:
            existing = db.query(Vulnerability).filter(
                Vulnerability.vit_number == record["vit_number"]
            ).first()

            if existing:
                # Track changes
                changes = []
                for field in ["state", "severity", "short_description", "assignment_group", "updated_at"]:
                    old_val = getattr(existing, field)
                    new_val = record.get(field)
                    if str(old_val) != str(new_val) and new_val is not None:
                        changes.append(VulnHistory(
                            vulnerability_id=existing.id,
                            field_changed=field,
                            old_value=str(old_val) if old_val else None,
                            new_value=str(new_val),
                        ))

                # Update existing record
                for field in ["cve_id", "hostname", "ip_address", "server_class", "severity",
                              "severity_level", "state", "short_description", "assignment_group",
                              "opened_at", "updated_at", "raw_description", "raw_recommendation"]:
                    val = record.get(field)
                    if val is not None:
                        setattr(existing, field, val)

                existing.last_import_at = datetime.utcnow()

                # Update or create analysis
                analysis_data = {
                    "cvss_score": record.get("cvss_score"),
                    "cvss_vector": record.get("cvss_vector"),
                    "attack_vector": record.get("attack_vector"),
                    "attack_complexity": record.get("attack_complexity"),
                    "privileges_required": record.get("privileges_required"),
                    "user_interaction": record.get("user_interaction"),
                    "affected_products": record.get("affected_products"),
                    "remediation_steps": record.get("remediation_steps"),
                    "detection_logic": record.get("detection_logic"),
                    "exploit_status": record.get("exploit_status"),
                }

                if existing.analysis:
                    for k, v in analysis_data.items():
                        if v is not None:
                            setattr(existing.analysis, k, v)
                else:
                    analysis = VulnAnalysis(vulnerability_id=existing.id, **analysis_data)
                    db.add(analysis)

                for change in changes:
                    db.add(change)

                retest_count += sync_retests(existing, record.get("work_notes"))

                updated_count += 1
            else:
                # Create new record
                vuln = Vulnerability(
                    vit_number=record["vit_number"],
                    cve_id=record["cve_id"],
                    hostname=record["hostname"],
                    ip_address=record.get("ip_address"),
                    server_class=record["server_class"],
                    severity=record["severity"],
                    severity_level=record["severity_level"],
                    state=record["state"],
                    short_description=record["short_description"],
                    assignment_group=record["assignment_group"],
                    opened_at=record.get("opened_at"),
                    updated_at=record.get("updated_at"),
                    raw_description=record["raw_description"],
                    raw_recommendation=record["raw_recommendation"],
                )
                db.add(vuln)
                db.flush()  # Get the ID

                analysis = VulnAnalysis(
                    vulnerability_id=vuln.id,
                    cvss_score=record.get("cvss_score"),
                    cvss_vector=record.get("cvss_vector"),
                    attack_vector=record.get("attack_vector"),
                    attack_complexity=record.get("attack_complexity"),
                    privileges_required=record.get("privileges_required"),
                    user_interaction=record.get("user_interaction"),
                    affected_products=record.get("affected_products"),
                    remediation_steps=record.get("remediation_steps"),
                    detection_logic=record.get("detection_logic"),
                    exploit_status=record.get("exploit_status"),
                )
                db.add(analysis)
                retest_count += sync_retests(vuln, record.get("work_notes"))
                new_count += 1

        except Exception as e:
            error_count += 1
            print(f"Error processing {record.get('vit_number')}: {e}")
            continue

    if commit:
        db.commit()
    else:
        db.flush()
    return {
        "new": new_count,
        "updated": updated_count,
        "errors": error_count,
        "retests": retest_count,
    }


def delete_existing_vulnerabilities(db: Session) -> int:
    """Delete vulnerabilities and ORM-cascaded child records without committing."""
    vulnerabilities = db.query(Vulnerability).all()
    for vulnerability in vulnerabilities:
        db.delete(vulnerability)
    db.flush()
    return len(vulnerabilities)


def process_excel_upload(
    db: Session,
    filepath: str,
    filename: str,
    *,
    replace_existing: bool = False,
) -> dict:
    """Main entry point: parse Excel and upsert into database."""
    records = parse_excel_to_records(filepath)
    if not records:
        raise ValueError("Excel 中未找到有效的漏洞工单，未修改现有数据")

    deleted_count = delete_existing_vulnerabilities(db) if replace_existing else 0
    counts = upsert_vulnerabilities(db, records, commit=False)

    # Log the upload
    log = UploadLog(
        filename=filename,
        total_rows=len(records),
        new_count=counts["new"],
        updated_count=counts["updated"],
        error_count=counts["errors"],
    )
    db.add(log)
    db.commit()

    return {
        "total_rows": len(records),
        "new": counts["new"],
        "updated": counts["updated"],
        "errors": counts["errors"],
        "retests": counts["retests"],
        "deleted": deleted_count,
    }
