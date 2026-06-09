import io
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from db.database import get_db
from services.vul_service import export_vulns_for_report, get_dashboard_stats

router = APIRouter()


@router.get("/api/reports/export")
async def export_excel(
    severity: Optional[str] = None,
    state: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Export vulnerabilities to Excel."""
    import pandas as pd

    data = export_vulns_for_report(db, severity=severity, state=state)
    if not data:
        return {"error": "No data to export"}

    df = pd.DataFrame(data)

    # Create Excel in memory
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, sheet_name="Vulnerabilities", index=False)

        # Add summary sheet
        stats = get_dashboard_stats(db)
        summary_df = pd.DataFrame([stats])
        summary_df.to_excel(writer, sheet_name="Summary", index=False)

    output.seek(0)
    filename = f"vuln_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/api/reports/weekly")
async def weekly_report(
    db: Session = Depends(get_db),
):
    """Generate weekly summary report."""
    stats = get_dashboard_stats(db)
    data = export_vulns_for_report(db, state="Open")

    report = {
        "title": "漏洞管理周报",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "总漏洞数": stats["total"],
            "严重漏洞": stats["critical"],
            "高危漏洞": stats["high"],
            "待修复": stats["open"],
            "已修复": stats["closed"],
            "修复率": f"{stats['fix_rate']}%",
            "超期漏洞(>30天)": stats["overdue"],
            "受影响主机": stats["hosts_affected"],
            "涉及CVE": stats["cve_count"],
        },
        "open_vulns_count": len(data),
    }

    return report
