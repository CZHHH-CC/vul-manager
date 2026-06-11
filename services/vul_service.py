import json
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import func, case, and_, extract
from sqlalchemy.orm import Session
from db.models import Vulnerability, VulnAnalysis, VulnHistory, UploadLog


# ─── Statistics ───────────────────────────────────────────────────────────────

def get_dashboard_stats(db: Session) -> dict:
    """Get summary statistics for the dashboard."""
    total = db.query(func.count(Vulnerability.id)).scalar() or 0
    critical = db.query(func.count(Vulnerability.id)).filter(Vulnerability.severity_level == 1).scalar() or 0
    high = db.query(func.count(Vulnerability.id)).filter(Vulnerability.severity_level == 2).scalar() or 0
    open_count = db.query(func.count(Vulnerability.id)).filter(Vulnerability.state == "Open").scalar() or 0
    closed_count = db.query(func.count(Vulnerability.id)).filter(Vulnerability.state.in_(["Closed", "Resolved"])).scalar() or 0
    in_progress = db.query(func.count(Vulnerability.id)).filter(Vulnerability.state == "In Progress").scalar() or 0
    hosts_affected = db.query(func.count(func.distinct(Vulnerability.hostname))).scalar() or 0
    cve_count = db.query(func.count(func.distinct(Vulnerability.cve_id))).scalar() or 0

    # Fix rate
    fix_rate = round(closed_count / total * 100, 1) if total > 0 else 0

    # Overdue (open > 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    overdue = db.query(func.count(Vulnerability.id)).filter(
        and_(Vulnerability.state == "Open", Vulnerability.opened_at < thirty_days_ago)
    ).scalar() or 0

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "open": open_count,
        "closed": closed_count,
        "in_progress": in_progress,
        "hosts_affected": hosts_affected,
        "cve_count": cve_count,
        "fix_rate": fix_rate,
        "overdue": overdue,
    }


def get_snow_kpi(db: Session) -> dict:
    """SNOW KPI metrics for currently OPEN vulnerabilities."""
    OPEN_STATES = ["Open", "In Progress"]
    base = db.query(Vulnerability).filter(Vulnerability.state.in_(OPEN_STATES))

    open_total = base.count()
    now = datetime.utcnow()

    # Severity distribution (open)
    sev = {1: 0, 2: 0, 3: 0, 4: 0}
    for lvl, cnt in db.query(Vulnerability.severity_level, func.count(Vulnerability.id))\
            .filter(Vulnerability.state.in_(OPEN_STATES))\
            .group_by(Vulnerability.severity_level).all():
        sev[lvl or 4] = cnt

    # Aging buckets by opened_at
    def aged(min_days, max_days=None):
        q = base.filter(Vulnerability.opened_at.isnot(None),
                        Vulnerability.opened_at < now - timedelta(days=min_days))
        if max_days is not None:
            q = q.filter(Vulnerability.opened_at >= now - timedelta(days=max_days))
        return q.count()

    overdue_30 = aged(30)
    aging = {
        "0-30天": base.filter(Vulnerability.opened_at >= now - timedelta(days=30)).count(),
        "30-60天": aged(30, 60),
        "60-90天": aged(60, 90),
        ">90天": aged(90),
    }

    cve_count = db.query(func.count(func.distinct(Vulnerability.cve_id)))\
        .filter(Vulnerability.state.in_(OPEN_STATES)).scalar() or 0
    hosts = db.query(func.count(func.distinct(Vulnerability.hostname)))\
        .filter(Vulnerability.state.in_(OPEN_STATES)).scalar() or 0

    # By server class (open)
    by_class = [
        {"class": r[0] or "Unknown", "count": r[1]}
        for r in db.query(Vulnerability.server_class, func.count(Vulnerability.id))
        .filter(Vulnerability.state.in_(OPEN_STATES))
        .group_by(Vulnerability.server_class)
        .order_by(func.count(Vulnerability.id).desc()).all()
    ]

    # By assignment group (open, top 10)
    by_group = [
        {"group": r[0] or "未分配", "count": r[1]}
        for r in db.query(Vulnerability.assignment_group, func.count(Vulnerability.id))
        .filter(Vulnerability.state.in_(OPEN_STATES))
        .group_by(Vulnerability.assignment_group)
        .order_by(func.count(Vulnerability.id).desc()).limit(10).all()
    ]

    return {
        "open_total": open_total,
        "overdue_30": overdue_30,
        "overdue_rate": round(overdue_30 / open_total * 100, 1) if open_total else 0,
        "critical": sev[1], "high": sev[2], "medium": sev[3], "low": sev[4],
        "cve_count": cve_count,
        "hosts_affected": hosts,
        "aging": aging,
        "by_class": by_class,
        "by_group": by_group,
    }


def get_severity_distribution(db: Session) -> list[dict]:
    """Get severity distribution for pie chart."""
    results = db.query(
        Vulnerability.severity,
        func.count(Vulnerability.id).label("count")
    ).group_by(Vulnerability.severity).all()

    return [{"severity": r[0] or "Unknown", "count": r[1]} for r in results]


def get_top_cves(db: Session, limit: int = 10) -> list[dict]:
    """Get top CVEs by affected host count."""
    results = db.query(
        Vulnerability.cve_id,
        func.count(func.distinct(Vulnerability.hostname)).label("host_count"),
        func.count(Vulnerability.id).label("ticket_count"),
        func.max(Vulnerability.severity).label("severity"),
    ).group_by(Vulnerability.cve_id).order_by(
        func.count(func.distinct(Vulnerability.hostname)).desc()
    ).limit(limit).all()

    return [
        {
            "cve_id": r[0],
            "host_count": r[1],
            "ticket_count": r[2],
            "severity": r[3],
        }
        for r in results
    ]


def get_state_distribution(db: Session) -> list[dict]:
    """Get state distribution for charts."""
    results = db.query(
        Vulnerability.state,
        func.count(Vulnerability.id).label("count")
    ).group_by(Vulnerability.state).all()

    return [{"state": r[0] or "Unknown", "count": r[1]} for r in results]


def get_class_distribution(db: Session) -> list[dict]:
    """Get server class distribution."""
    results = db.query(
        Vulnerability.server_class,
        func.count(Vulnerability.id).label("count")
    ).group_by(Vulnerability.server_class).all()

    return [{"class": r[0] or "Unknown", "count": r[1]} for r in results]


def get_weekly_trends(db: Session, weeks: int = 12) -> list[dict]:
    """Get weekly vulnerability trends."""
    from config import DATABASE_URL
    cutoff = datetime.utcnow() - timedelta(weeks=weeks)

    if DATABASE_URL.startswith("sqlite"):
        # SQLite date functions
        week_expr = func.strftime("%Y-%W", Vulnerability.opened_at).label("week")
    else:
        # PostgreSQL date functions
        week_expr = func.date_trunc("week", Vulnerability.opened_at).label("week")

    results = db.query(
        week_expr,
        func.count(Vulnerability.id).label("count"),
        func.sum(case((Vulnerability.severity_level == 1, 1), else_=0)).label("critical"),
        func.sum(case((Vulnerability.severity_level == 2, 1), else_=0)).label("high"),
    ).filter(
        Vulnerability.opened_at >= cutoff
    ).group_by(week_expr).order_by(week_expr).all()

    return [
        {
            "week": r[0].strftime("%Y-%m-%d") if hasattr(r[0], 'strftime') else str(r[0]) if r[0] else None,
            "count": r[1],
            "critical": r[2],
            "high": r[3],
        }
        for r in results
    ]


# ─── Vulnerability CRUD ──────────────────────────────────────────────────────

def get_vuln_list(
    db: Session,
    severity: Optional[str] = None,
    state: Optional[str] = None,
    cve_id: Optional[str] = None,
    hostname: Optional[str] = None,
    server_class: Optional[str] = None,
    ai_status: Optional[str] = None,
    fix_plan_status: Optional[str] = None,
    assignment_group: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "severity_level",
    sort_order: str = "asc",
    page: int = 1,
    page_size: int = 50,
) -> dict:
    """Get paginated, filtered vulnerability list."""
    query = db.query(Vulnerability)

    # Apply filters
    if severity:
        query = query.filter(Vulnerability.severity.ilike(f"%{severity}%"))
    if state:
        query = query.filter(Vulnerability.state == state)
    if cve_id:
        query = query.filter(Vulnerability.cve_id.ilike(f"%{cve_id}%"))
    if hostname:
        query = query.filter(Vulnerability.hostname.ilike(f"%{hostname}%"))
    if server_class:
        query = query.filter(Vulnerability.server_class == server_class)
    if ai_status:
        if ai_status == "analyzed":
            query = query.join(VulnAnalysis).filter(VulnAnalysis.ai_risk_summary.isnot(None))
        elif ai_status == "rule_based":
            query = query.join(VulnAnalysis).filter(
                VulnAnalysis.ai_risk_summary.is_(None),
                VulnAnalysis.ai_fix_priority.isnot(None)
            )
        elif ai_status == "pending":
            query = query.outerjoin(VulnAnalysis).filter(
                (VulnAnalysis.id.is_(None)) |
                (VulnAnalysis.ai_risk_summary.is_(None) & VulnAnalysis.ai_fix_priority.is_(None))
            )
    if fix_plan_status:
        # Use EXISTS (relationship.has) so it composes with ai_status' join
        if fix_plan_status == "done":
            query = query.filter(Vulnerability.analysis.has(VulnAnalysis.ai_fix_plan.isnot(None)))
        elif fix_plan_status == "pending":
            query = query.filter(~Vulnerability.analysis.has(VulnAnalysis.ai_fix_plan.isnot(None)))
    if assignment_group:
        query = query.filter(Vulnerability.assignment_group.ilike(f"%{assignment_group}%"))
    if search:
        query = query.filter(
            (Vulnerability.vit_number.ilike(f"%{search}%")) |
            (Vulnerability.cve_id.ilike(f"%{search}%")) |
            (Vulnerability.short_description.ilike(f"%{search}%"))
        )

    # Total count
    total = query.count()

    # Sorting
    sort_column = getattr(Vulnerability, sort_by, Vulnerability.severity_level)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Pagination
    offset = (page - 1) * page_size
    vulns = query.offset(offset).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (total + page_size - 1) // page_size,
        "items": vulns,
    }


def get_vuln_detail(db: Session, vit_number: str) -> Optional[Vulnerability]:
    """Get single vulnerability detail."""
    return db.query(Vulnerability).filter(Vulnerability.vit_number == vit_number).first()


def update_vuln_state(db: Session, vit_number: str, new_state: str) -> Optional[Vulnerability]:
    """Update vulnerability state and log the change."""
    vuln = db.query(Vulnerability).filter(Vulnerability.vit_number == vit_number).first()
    if not vuln:
        return None

    old_state = vuln.state
    if old_state != new_state:
        history = VulnHistory(
            vulnerability_id=vuln.id,
            field_changed="state",
            old_value=old_state,
            new_value=new_state,
        )
        db.add(history)
        vuln.state = new_state
        db.commit()

    return vuln


def get_vuln_history(db: Session, vit_number: str) -> list[VulnHistory]:
    """Get change history for a vulnerability."""
    vuln = db.query(Vulnerability).filter(Vulnerability.vit_number == vit_number).first()
    if not vuln:
        return []
    return db.query(VulnHistory).filter(
        VulnHistory.vulnerability_id == vuln.id
    ).order_by(VulnHistory.changed_at.desc()).all()


# ─── Overdue Detection ───────────────────────────────────────────────────────

def get_overdue_vulns(db: Session, days: int = 30) -> list[Vulnerability]:
    """Get vulnerabilities open longer than N days."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    return db.query(Vulnerability).filter(
        and_(Vulnerability.state == "Open", Vulnerability.opened_at < cutoff)
    ).order_by(Vulnerability.opened_at.asc()).all()


# ─── Filter Options ──────────────────────────────────────────────────────────

def get_filter_options(db: Session) -> dict:
    """Get distinct values for filter dropdowns."""
    severities = [r[0] for r in db.query(func.distinct(Vulnerability.severity)).all() if r[0]]
    states = [r[0] for r in db.query(func.distinct(Vulnerability.state)).all() if r[0]]
    classes = [r[0] for r in db.query(func.distinct(Vulnerability.server_class)).all() if r[0]]
    groups = [r[0] for r in db.query(func.distinct(Vulnerability.assignment_group)).all() if r[0]]

    return {
        "severities": sorted(severities),
        "states": sorted(states),
        "classes": sorted(classes),
        "assignment_groups": sorted(groups),
    }


# ─── Upload History ──────────────────────────────────────────────────────────

def get_upload_history(db: Session, limit: int = 10) -> list[UploadLog]:
    """Get recent upload history."""
    return db.query(UploadLog).order_by(UploadLog.uploaded_at.desc()).limit(limit).all()


# ─── Export ───────────────────────────────────────────────────────────────────

def _format_components(json_str: Optional[str]) -> str:
    """Format detected_components JSON into a readable multi-line string (name version — path)."""
    if not json_str:
        return ""
    try:
        items = json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return ""
    lines = []
    for c in items:
        name = (c.get("name") or "").strip()
        ver = (c.get("version") or "").strip()
        path = (c.get("path") or "").strip()
        seg = " ".join(x for x in [name, ver] if x)
        if path:
            seg = f"{seg} — {path}" if seg else path
        if seg:
            lines.append(seg)
    return "\n".join(lines)


def _format_fix_plan(json_str: Optional[str]) -> str:
    """Format ai_fix_plan JSON into a concise readable string for export."""
    if not json_str:
        return ""
    try:
        p = json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return ""
    if p.get("plan_type") == "upgrade":
        lines = []
        if p.get("summary"):
            lines.append(p["summary"])
        for c in p.get("components", []):
            name = (c.get("name") or "").strip()
            cur = (c.get("current_version") or "").strip()
            aff = (c.get("affected") or "").strip()
            fixed = (c.get("fixed_version") or "").strip()
            lines.append(f"· {name} 当前 {cur or 'N/A'} [{aff or 'N/A'}] → 升级到 {fixed or 'N/A'}")
        return "\n".join(lines)
    # runbook
    lines = []
    if p.get("fix_summary"):
        lines.append(p["fix_summary"])
    for s in p.get("fix_steps", []):
        action = (s.get("action") or "").strip()
        cmd = (s.get("command") or "").strip()
        lines.append(f"{s.get('step', '')}. {action}" + (f"  [{cmd}]" if cmd else ""))
    return "\n".join(lines)


def export_vulns_for_report(db: Session, severity: Optional[str] = None, state: Optional[str] = None) -> list[dict]:
    """Export vulnerabilities as list of dicts for Excel/report generation."""
    query = db.query(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity.ilike(f"%{severity}%"))
    if state:
        query = query.filter(Vulnerability.state == state)

    vulns = query.order_by(Vulnerability.severity_level.asc(), Vulnerability.opened_at.asc()).all()

    result = []
    for v in vulns:
        a = v.analysis
        result.append({
            "VIT编号": v.vit_number,
            "CVE编号": v.cve_id,
            "主机名": v.hostname,
            "IP地址": v.ip_address or "",
            "服务器类型": v.server_class,
            "服务器版本": (a.os_version if a and a.os_version else ""),
            "严重程度": v.severity,
            "状态": v.state,
            "CVSS评分": a.cvss_score if a else "",
            "利用状态": a.exploit_status if a else "",
            "修复优先级": a.ai_fix_priority if a else "",
            "检测到的组件": _format_components(a.detected_components if a else None),
            "操作指南": a.ai_remediation_guide if a and a.ai_remediation_guide else "",
            "修复方案": _format_fix_plan(a.ai_fix_plan if a else None),
            "负责团队": v.assignment_group or "",
            "创建时间": v.opened_at.strftime("%Y-%m-%d") if v.opened_at else "",
            "更新时间": v.updated_at.strftime("%Y-%m-%d") if v.updated_at else "",
        })

    return result


# ─── Batch Delete ────────────────────────────────────────────────────────────

def delete_vulns_by_numbers(db: Session, vit_numbers: list[str]) -> int:
    """Delete vulnerabilities by vit_number list. Returns count deleted."""
    vulns = db.query(Vulnerability).filter(
        Vulnerability.vit_number.in_(vit_numbers)
    ).all()

    count = len(vulns)
    for v in vulns:
        db.delete(v)

    db.commit()
    return count
