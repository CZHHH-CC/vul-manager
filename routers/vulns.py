from typing import Optional
from fastapi import APIRouter, Depends, Request, Query, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db.database import get_db, SessionLocal
from db.models import Vulnerability
from services.vul_service import (
    get_vuln_list, get_vuln_detail, update_vuln_state,
    get_vuln_history, get_filter_options, get_overdue_vulns,
    delete_vulns_by_numbers,
)
from services.ai_analyzer import analyze_vulnerabilities, generate_and_review_fix_plan
from services.cve_lookup import enrich_cvss_scores, count_missing_cvss
from services.detection_parser import parse_detection_logic
from routers.settings import get_ai_settings

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/vulns", response_class=HTMLResponse)
async def vuln_list_page(
    request: Request,
    severity: Optional[str] = None,
    state: Optional[str] = None,
    cve_id: Optional[str] = None,
    hostname: Optional[str] = None,
    ai_status: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "severity_level",
    sort_order: str = "asc",
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
):
    """Render vulnerability list page."""
    result = get_vuln_list(
        db, severity=severity, state=state, cve_id=cve_id,
        hostname=hostname, ai_status=ai_status, search=search,
        sort_by=sort_by, sort_order=sort_order, page=page, page_size=page_size,
    )
    filters = get_filter_options(db)

    return templates.TemplateResponse("vuln_list.html", {
        "request": request,
        "vulns": result["items"],
        "total": result["total"],
        "page": result["page"],
        "page_size": result["page_size"],
        "total_pages": result["total_pages"],
        "filters": filters,
        "current_filters": {
            "severity": severity,
            "state": state,
            "cve_id": cve_id,
            "hostname": hostname,
            "ai_status": ai_status,
            "search": search,
            "sort_by": sort_by,
            "sort_order": sort_order,
        },
    })


@router.get("/api/vulns")
async def list_vulns_api(
    severity: Optional[str] = None,
    state: Optional[str] = None,
    cve_id: Optional[str] = None,
    hostname: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "severity_level",
    sort_order: str = "asc",
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
):
    """API: List vulnerabilities with filters."""
    result = get_vuln_list(
        db, severity=severity, state=state, cve_id=cve_id,
        hostname=hostname, search=search, sort_by=sort_by,
        sort_order=sort_order, page=page, page_size=page_size,
    )
    return {
        "total": result["total"],
        "page": result["page"],
        "total_pages": result["total_pages"],
        "items": [
            {
                "vit_number": v.vit_number,
                "cve_id": v.cve_id,
                "hostname": v.hostname,
                "severity": v.severity,
                "state": v.state,
                "server_class": v.server_class,
                "assignment_group": v.assignment_group,
                "opened_at": v.opened_at.isoformat() if v.opened_at else None,
                "cvss_score": v.analysis.cvss_score if v.analysis else None,
                "ai_fix_priority": v.analysis.ai_fix_priority if v.analysis else None,
            }
            for v in result["items"]
        ],
    }


@router.get("/vulns/{vit_number}", response_class=HTMLResponse)
async def vuln_detail_page(
    request: Request,
    vit_number: str,
    db: Session = Depends(get_db),
):
    """Render vulnerability detail page."""
    vuln = get_vuln_detail(db, vit_number)
    if not vuln:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    history = get_vuln_history(db, vit_number)

    # Try AI-extracted components first, fall back to regex parser
    detected_components = []
    if vuln.analysis and vuln.analysis.detected_components:
        try:
            import json
            detected_components = json.loads(vuln.analysis.detected_components)
        except (json.JSONDecodeError, TypeError):
            pass
    if not detected_components and vuln.analysis:
        detected_components = parse_detection_logic(vuln.analysis.detection_logic)

    return templates.TemplateResponse("vuln_detail.html", {
        "request": request,
        "vuln": vuln,
        "analysis": vuln.analysis,
        "history": history,
        "detected_components": detected_components,
    })


@router.patch("/api/vulns/{vit_number}")
async def update_vuln(
    vit_number: str,
    state: str = Query(...),
    db: Session = Depends(get_db),
):
    """API: Update vulnerability state."""
    vuln = update_vuln_state(db, vit_number, state)
    if not vuln:
        return {"error": "Vulnerability not found"}
    return {
        "success": True,
        "vit_number": vuln.vit_number,
        "state": vuln.state,
    }


class BatchDeleteRequest(BaseModel):
    vit_numbers: list[str]


@router.delete("/api/vulns")
async def batch_delete_vulns(
    body: BatchDeleteRequest,
    db: Session = Depends(get_db),
):
    """API: Batch delete vulnerabilities by vit_number list."""
    if not body.vit_numbers:
        return {"error": "请提供要删除的漏洞编号"}
    deleted = delete_vulns_by_numbers(db, body.vit_numbers)
    return {"success": True, "deleted": deleted}


@router.post("/api/vulns/analyze")
async def trigger_analysis(
    vit_numbers: Optional[list[str]] = None,
    db: Session = Depends(get_db),
):
    """API: Trigger AI analysis."""
    ai_settings = get_ai_settings(db)
    result = await analyze_vulnerabilities(db, ai_settings, vit_numbers)
    return result


async def _run_cvss_enrich(nvd_api_key: str):
    """Background task: enrich missing CVSS scores from NVD."""
    db = SessionLocal()
    try:
        await enrich_cvss_scores(db, api_key=nvd_api_key or None)
    except Exception as e:
        print(f"CVSS enrichment failed: {e}")
    finally:
        db.close()


@router.post("/api/vulns/enrich-cvss")
async def trigger_cvss_enrich(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """API: Enrich missing CVSS scores from NVD (runs in background)."""
    pending = count_missing_cvss(db)
    if pending == 0:
        return {"success": True, "pending": 0, "message": "没有需要补全的 CVSS（所有带 CVE 的漏洞均已有评分）"}

    nvd_key = get_ai_settings(db).get("nvd_api_key", "")
    background_tasks.add_task(_run_cvss_enrich, nvd_key)

    eta = round(pending * (0.7 if nvd_key else 6.5) / 60, 1)
    note = "" if nvd_key else "（未配置 NVD API Key，速度受限；可在设置中填入 Key 加速）"
    return {
        "success": True,
        "pending": pending,
        "message": f"已在后台开始从 NVD 补全 {pending} 个 CVE 的 CVSS，预计约 {eta} 分钟，完成后刷新查看。{note}",
    }


@router.post("/api/vulns/{vit_number}/fix-plan")
async def create_fix_plan(
    vit_number: str,
    db: Session = Depends(get_db),
):
    """API: Generate and review fix plan for a vulnerability."""
    ai_settings = get_ai_settings(db)
    result = await generate_and_review_fix_plan(db, vit_number, ai_settings)
    return result


@router.get("/api/filter-options")
async def filter_options(db: Session = Depends(get_db)):
    """API: Get filter options."""
    return get_filter_options(db)


@router.get("/api/overdue")
async def overdue_vulns(days: int = 30, db: Session = Depends(get_db)):
    """API: Get overdue vulnerabilities."""
    vulns = get_overdue_vulns(db, days)
    return {
        "count": len(vulns),
        "items": [
            {
                "vit_number": v.vit_number,
                "cve_id": v.cve_id,
                "hostname": v.hostname,
                "severity": v.severity,
                "opened_at": v.opened_at.isoformat() if v.opened_at else None,
                "days_open": (v.opened_at - v.opened_at).days if v.opened_at else None,
            }
            for v in vulns[:50]
        ],
    }
