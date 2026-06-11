import io
from datetime import datetime
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from db.database import get_db
from services.vul_service import get_snow_kpi

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/kpi", response_class=HTMLResponse)
async def kpi_page(request: Request, db: Session = Depends(get_db)):
    """SNOW KPI statistics page (open vulnerabilities)."""
    kpi = get_snow_kpi(db)
    return templates.TemplateResponse("kpi.html", {"request": request, "kpi": kpi})


@router.get("/api/reports/kpi/pdf")
async def kpi_pdf(db: Session = Depends(get_db)):
    """Export SNOW KPI report as PDF."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    )

    kpi = get_snow_kpi(db)

    # Chinese font (built-in CID font, no external file needed)
    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    CN = "STSong-Light"

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1cn", parent=styles["Title"], fontName=CN, fontSize=18)
    h2 = ParagraphStyle("h2cn", parent=styles["Heading2"], fontName=CN, fontSize=12)
    normal = ParagraphStyle("ncn", parent=styles["Normal"], fontName=CN, fontSize=9)
    muted = ParagraphStyle("mcn", parent=styles["Normal"], fontName=CN, fontSize=8, textColor=colors.grey)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm,
                            leftMargin=16 * mm, rightMargin=16 * mm, title="SNOW KPI 统计报告")
    story = []

    story.append(Paragraph("SNOW KPI 统计报告", h1))
    story.append(Paragraph(f"统计范围：当前未关闭漏洞（Open / In Progress）　生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M')}", muted))
    story.append(Spacer(1, 8 * mm))

    def kpi_table(rows, col_widths):
        t = Table(rows, colWidths=col_widths)
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), CN),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f5f5f5")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#171717")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e5e5")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        return t

    # Core metrics
    story.append(Paragraph("核心指标", h2))
    story.append(Spacer(1, 2 * mm))
    core = [
        ["未关闭漏洞总数", str(kpi["open_total"]), "超期未修复(>30天)", f'{kpi["overdue_30"]}（{kpi["overdue_rate"]}%）'],
        ["涉及 CVE 数", str(kpi["cve_count"]), "受影响主机数", str(kpi["hosts_affected"])],
    ]
    story.append(kpi_table(core, [42 * mm, 35 * mm, 45 * mm, 35 * mm]))
    story.append(Spacer(1, 6 * mm))

    # Severity
    story.append(Paragraph("严重程度分布（未关闭）", h2))
    story.append(Spacer(1, 2 * mm))
    sev = [["严重", "高危", "中危", "低危"],
           [str(kpi["critical"]), str(kpi["high"]), str(kpi["medium"]), str(kpi["low"])]]
    story.append(kpi_table(sev, [39 * mm] * 4))
    story.append(Spacer(1, 6 * mm))

    # Aging
    story.append(Paragraph("漏洞时效分布", h2))
    story.append(Spacer(1, 2 * mm))
    aging = kpi["aging"]
    aging_rows = [list(aging.keys()), [str(v) for v in aging.values()]]
    story.append(kpi_table(aging_rows, [39 * mm] * 4))
    story.append(Spacer(1, 6 * mm))

    # By class
    if kpi["by_class"]:
        story.append(Paragraph("按服务器类型分布", h2))
        story.append(Spacer(1, 2 * mm))
        rows = [["服务器类型", "数量"]] + [[c["class"], str(c["count"])] for c in kpi["by_class"]]
        story.append(kpi_table(rows, [110 * mm, 40 * mm]))
        story.append(Spacer(1, 6 * mm))

    # By assignment group
    if kpi["by_group"]:
        story.append(Paragraph("按负责团队分布（Top 10）", h2))
        story.append(Spacer(1, 2 * mm))
        rows = [["负责团队", "数量"]] + [[g["group"], str(g["count"])] for g in kpi["by_group"]]
        story.append(kpi_table(rows, [110 * mm, 40 * mm]))

    doc.build(story)
    buf.seek(0)
    filename = f"snow_kpi_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        buf, media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
