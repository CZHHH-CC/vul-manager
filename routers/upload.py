import os
import tempfile
from fastapi import APIRouter, UploadFile, File, Depends, Request, Form, BackgroundTasks
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from db.database import get_db, SessionLocal
from services.excel_parser import process_excel_upload
from services.ai_analyzer import analyze_vulnerabilities, generate_fix_plans_bulk
from services.vul_service import get_upload_history
from routers.settings import get_ai_settings

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request, db: Session = Depends(get_db)):
    """Render upload page."""
    history = get_upload_history(db)
    return templates.TemplateResponse("upload.html", {
        "request": request,
        "history": history,
    })


async def _run_ai_analysis(auto_fix_plan: bool = False):
    """Background task: run AI analysis (and optionally fix plans) on vulns."""
    db = SessionLocal()
    try:
        ai_settings = get_ai_settings(db)
        ar = await analyze_vulnerabilities(db, ai_settings)
        print(f"[auto] analyze done: {ar}")
        if auto_fix_plan:
            # Fix plans depend on analysis existing first, so run after.
            fr = await generate_fix_plans_bulk(db, ai_settings)
            print(f"[auto] fix plans done: {fr}")
    except Exception as e:
        import traceback
        print(f"[auto] AI task failed: {e}")
        traceback.print_exc()
    finally:
        db.close()


@router.post("/api/upload")
async def upload_excel(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    auto_analyze: str = Form("false"),
    auto_fix_plan: str = Form("false"),
    db: Session = Depends(get_db),
):
    """Upload and process Excel file."""
    if not file.filename.endswith((".xlsx", ".xls")):
        return {"error": "Please upload an Excel file (.xlsx or .xls)"}

    # Save to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = process_excel_upload(db, tmp_path, file.filename)
        response = {
            "success": True,
            "message": f"处理完成: 新增 {result['new']} 条, 更新 {result['updated']} 条, 失败 {result['errors']} 条",
            "ai_triggered": False,
            **result,
        }

        # Trigger AI analysis (and optionally fix plans) in background if requested
        want_analyze = auto_analyze.lower() == "true"
        want_fix_plan = auto_fix_plan.lower() == "true"
        if want_analyze or want_fix_plan:
            ai_settings = get_ai_settings(db)
            if ai_settings.get("ai_enabled") and ai_settings.get("ai_api_key"):
                background_tasks.add_task(_run_ai_analysis, want_fix_plan)
                response["ai_triggered"] = True
                if want_fix_plan:
                    response["message"] += "（已在后台启动 AI 分析 + 修复方案生成，耗时较长，请稍后刷新）"
            else:
                response["message"] += " (AI 未配置，跳过自动分析)"

        return response
    except Exception as e:
        return {"error": f"Processing failed: {str(e)}"}
    finally:
        os.unlink(tmp_path)
