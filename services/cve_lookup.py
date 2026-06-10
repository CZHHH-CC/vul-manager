"""Lookup CVSS scores from NVD (National Vulnerability Database) by CVE ID."""

import asyncio
import httpx
from sqlalchemy.orm import Session
from db.models import Vulnerability, VulnAnalysis

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_DELAY = 0.6  # NVD rate limit: ~5 requests without API key


async def fetch_cvss_for_cve(client: httpx.AsyncClient, cve_id: str) -> dict | None:
    """Query NVD API for CVSS data of a single CVE ID."""
    try:
        resp = await client.get(NVD_API_URL, params={"cveId": cve_id}, timeout=15)
        if resp.status_code == 403:
            return None  # Rate limited
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        metrics = vulns[0]["cve"].get("metrics", {})

        # Prefer CVSS v3.1, fallback to v3.0, then v2
        for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            entries = metrics.get(version_key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                return {
                    "cvss_score": cvss_data.get("baseScore"),
                    "cvss_vector": cvss_data.get("vectorString"),
                    "attack_vector": cvss_data.get("attackVector"),
                    "attack_complexity": cvss_data.get("attackComplexity"),
                    "privileges_required": cvss_data.get("privilegesRequired"),
                    "user_interaction": cvss_data.get("userInteraction"),
                }
        return None
    except Exception:
        return None


async def enrich_cvss_scores(db: Session, cve_ids: list[str] | None = None) -> dict:
    """Batch lookup CVSS scores for vulnerabilities missing them.

    Args:
        db: Database session
        cve_ids: Optional list of CVE IDs to look up. If None, looks up all
                 vulnerabilities with missing CVSS scores.

    Returns:
        Summary dict with updated/skipped/failed counts.
    """
    # Find vulns that need CVSS lookup
    query = db.query(Vulnerability).join(
        VulnAnalysis, Vulnerability.id == VulnAnalysis.vulnerability_id
    ).filter(VulnAnalysis.cvss_score.is_(None))

    if cve_ids:
        query = query.filter(Vulnerability.cve_id.in_(cve_ids))

    vulns = query.all()

    # Deduplicate by CVE ID
    cve_to_vulns: dict[str, list[Vulnerability]] = {}
    for v in vulns:
        if v.cve_id and v.cve_id.startswith("CVE-"):
            cve_to_vulns.setdefault(v.cve_id, []).append(v)

    if not cve_to_vulns:
        return {"total": 0, "updated": 0, "skipped": 0, "failed": 0}

    updated = 0
    failed = 0

    async with httpx.AsyncClient() as client:
        for cve_id, related_vulns in cve_to_vulns.items():
            await asyncio.sleep(REQUEST_DELAY)
            cvss = await fetch_cvss_for_cve(client, cve_id)

            if cvss and cvss["cvss_score"] is not None:
                for v in related_vulns:
                    if v.analysis:
                        v.analysis.cvss_score = cvss["cvss_score"]
                        v.analysis.cvss_vector = cvss.get("cvss_vector") or v.analysis.cvss_vector
                        v.analysis.attack_vector = cvss.get("attack_vector") or v.analysis.attack_vector
                        v.analysis.attack_complexity = cvss.get("attack_complexity") or v.analysis.attack_complexity
                        v.analysis.privileges_required = cvss.get("privileges_required") or v.analysis.privileges_required
                        v.analysis.user_interaction = cvss.get("user_interaction") or v.analysis.user_interaction
                        updated += 1
            else:
                failed += 1

    db.commit()

    return {
        "total": len(cve_to_vulns),
        "updated": updated,
        "skipped": len(vulns) - updated,
        "failed": failed,
    }
