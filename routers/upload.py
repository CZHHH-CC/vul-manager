import os
import tempfile
from fastapi import APIRouter, UploadFile, File, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from db.database import get_db
from services.excel_parser import process_excel_upload
from services.vul_service import get_upload_history

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


@router.post("/api/upload")
async def upload_excel(file: UploadFile = File(...), db: Session = Depends(get_db)):
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
        return {
            "success": True,
            "message": f"处理完成: 新增 {result['new']} 条, 更新 {result['updated']} 条, 失败 {result['errors']} 条",
            **result,
        }
    except Exception as e:
        return {"error": f"Processing failed: {str(e)}"}
    finally:
        os.unlink(tmp_path)
