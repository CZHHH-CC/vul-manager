from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from db.database import get_db
from services.vul_service import (
    get_dashboard_stats, get_severity_distribution, get_top_cves,
    get_state_distribution, get_class_distribution, get_weekly_trends,
    get_overdue_vulns,
)

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request, db: Session = Depends(get_db)):
    """Render main dashboard."""
    stats = get_dashboard_stats(db)
    severity_dist = get_severity_distribution(db)
    top_cves = get_top_cves(db, limit=10)
    state_dist = get_state_distribution(db)
    class_dist = get_class_distribution(db)
    trends = get_weekly_trends(db, weeks=12)
    overdue = get_overdue_vulns(db, days=30)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": stats,
        "severity_dist": severity_dist,
        "top_cves": top_cves,
        "state_dist": state_dist,
        "class_dist": class_dist,
        "trends": trends,
        "overdue": overdue[:10],  # Top 10 overdue
    })


@router.get("/api/dashboard/stats")
async def dashboard_stats_api(db: Session = Depends(get_db)):
    """API: Dashboard statistics."""
    return get_dashboard_stats(db)


@router.get("/api/dashboard/severity")
async def severity_distribution_api(db: Session = Depends(get_db)):
    """API: Severity distribution."""
    return get_severity_distribution(db)


@router.get("/api/dashboard/top-cves")
async def top_cves_api(limit: int = 10, db: Session = Depends(get_db)):
    """API: Top CVEs by host count."""
    return get_top_cves(db, limit)


@router.get("/api/dashboard/states")
async def state_distribution_api(db: Session = Depends(get_db)):
    """API: State distribution."""
    return get_state_distribution(db)


@router.get("/api/dashboard/classes")
async def class_distribution_api(db: Session = Depends(get_db)):
    """API: Server class distribution."""
    return get_class_distribution(db)


@router.get("/api/dashboard/trends")
async def trends_api(weeks: int = 12, db: Session = Depends(get_db)):
    """API: Weekly trends."""
    return get_weekly_trends(db, weeks)
