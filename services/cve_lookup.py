"""Lookup CVSS scores from NVD (National Vulnerability Database) by CVE ID."""

import asyncio
import httpx
from sqlalchemy.orm import Session
from db.models import Vulnerability, VulnAnalysis

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD rate limits (rolling 30s window):
#   - without API key: 5 requests  -> ~1 req / 6s
#   - with    API key: 50 requests -> ~1 req / 0.6s
DELAY_WITH_KEY = 0.7
DELAY_NO_KEY = 6.5
MAX_RETRIES = 3


async def fetch_cvss_for_cve(client: httpx.AsyncClient, cve_id: str,
                             api_key: str | None = None) -> dict | None:
    """Query NVD API for CVSS data of a single CVE ID, retrying on rate-limit."""
    headers = {"apiKey": api_key} if api_key else {}

    for attempt in range(MAX_RETRIES):
        try:
            resp = await client.get(NVD_API_URL, params={"cveId": cve_id},
                                    headers=headers, timeout=20)
            # 403/429 -> rate limited, back off and retry
            if resp.status_code in (403, 429):
                await asyncio.sleep((attempt + 1) * (DELAY_NO_KEY if not api_key else DELAY_WITH_KEY))
                continue
            resp.raise_for_status()
            data = resp.json()

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None  # CVE not found in NVD

            metrics = vulns[0]["cve"].get("metrics", {})
            # Prefer CVSS v3.1 -> v3.0 -> v2
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
            return None  # found but no CVSS metrics published
        except (httpx.TimeoutException, httpx.TransportError):
            await asyncio.sleep((attempt + 1) * 1.5)
            continue
        except Exception:
            return None
    return None  # exhausted retries (rate limited)


async def enrich_cvss_scores(db: Session, cve_ids: list[str] | None = None,
                             api_key: str | None = None) -> dict:
    """Batch lookup CVSS scores for vulnerabilities missing them.

    Args:
        db: Database session
        cve_ids: Optional list of CVE IDs to look up. If None, looks up all
                 vulnerabilities with missing CVSS scores.
        api_key: Optional NVD API key (much higher rate limit).

    Returns:
        Summary dict with total/updated/failed counts.
    """
    query = db.query(Vulnerability).join(
        VulnAnalysis, Vulnerability.id == VulnAnalysis.vulnerability_id
    ).filter(VulnAnalysis.cvss_score.is_(None))

    if cve_ids:
        query = query.filter(Vulnerability.cve_id.in_(cve_ids))

    vulns = query.all()

    # Deduplicate by CVE ID (one NVD call updates all rows sharing the CVE)
    cve_to_vulns: dict[str, list[Vulnerability]] = {}
    for v in vulns:
        if v.cve_id and v.cve_id.startswith("CVE-"):
            cve_to_vulns.setdefault(v.cve_id, []).append(v)

    if not cve_to_vulns:
        return {"total_cves": 0, "updated_rows": 0, "not_found": 0, "failed": 0}

    delay = DELAY_WITH_KEY if api_key else DELAY_NO_KEY
    updated_rows = 0
    not_found = 0
    failed = 0

    async with httpx.AsyncClient() as client:
        for cve_id, related_vulns in cve_to_vulns.items():
            cvss = await fetch_cvss_for_cve(client, cve_id, api_key)

            if cvss and cvss["cvss_score"] is not None:
                for v in related_vulns:
                    if v.analysis:
                        v.analysis.cvss_score = cvss["cvss_score"]
                        v.analysis.cvss_vector = cvss.get("cvss_vector") or v.analysis.cvss_vector
                        v.analysis.attack_vector = cvss.get("attack_vector") or v.analysis.attack_vector
                        v.analysis.attack_complexity = cvss.get("attack_complexity") or v.analysis.attack_complexity
                        v.analysis.privileges_required = cvss.get("privileges_required") or v.analysis.privileges_required
                        v.analysis.user_interaction = cvss.get("user_interaction") or v.analysis.user_interaction
                        updated_rows += 1
                db.commit()
            elif cvss is None:
                failed += 1  # rate-limited / network / not in NVD
            else:
                not_found += 1

            await asyncio.sleep(delay)

    return {
        "total_cves": len(cve_to_vulns),
        "updated_rows": updated_rows,
        "not_found": not_found,
        "failed": failed,
    }


def count_missing_cvss(db: Session) -> int:
    """Count distinct CVEs that are missing a CVSS score (for UI feedback)."""
    rows = db.query(Vulnerability.cve_id).join(
        VulnAnalysis, Vulnerability.id == VulnAnalysis.vulnerability_id
    ).filter(
        VulnAnalysis.cvss_score.is_(None),
        Vulnerability.cve_id.like("CVE-%"),
    ).distinct().all()
    return len(rows)
