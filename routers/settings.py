from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import httpx
from db.database import get_db
from db.models import Settings

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Default AI settings
AI_DEFAULTS = {
    "ai_enabled": {"value": "false", "description": "是否启用AI分析功能"},
    "ai_provider": {"value": "", "description": "AI服务商 (openai/anthropic/deepseek/bailian/volcengine)"},
    "ai_api_key": {"value": "", "description": "API密钥"},
    "ai_base_url": {"value": "https://api.openai.com/v1", "description": "API地址 (自定义时使用)"},
    "ai_model": {"value": "gpt-4o-mini", "description": "模型名称"},
}


def init_default_settings(db: Session):
    """Initialize default settings if not exists."""
    for key, info in AI_DEFAULTS.items():
        existing = db.query(Settings).filter(Settings.key == key).first()
        if not existing:
            setting = Settings(key=key, value=info["value"], description=info["description"])
            db.add(setting)
    db.commit()


def get_setting(db: Session, key: str) -> str:
    """Get a setting value by key."""
    setting = db.query(Settings).filter(Settings.key == key).first()
    if setting:
        return setting.value or ""
    return AI_DEFAULTS.get(key, {}).get("value", "")


def get_ai_settings(db: Session) -> dict:
    """Get all AI settings as a dict."""
    init_default_settings(db)
    return {
        "ai_enabled": get_setting(db, "ai_enabled") == "true",
        "ai_provider": get_setting(db, "ai_provider"),
        "ai_api_key": get_setting(db, "ai_api_key"),
        "ai_base_url": get_setting(db, "ai_base_url"),
        "ai_model": get_setting(db, "ai_model"),
    }


class SettingUpdate(BaseModel):
    key: str
    value: str


class AISettingsUpdate(BaseModel):
    ai_enabled: bool
    ai_provider: Optional[str] = ""
    ai_api_key: Optional[str] = ""
    ai_base_url: Optional[str] = ""
    ai_model: Optional[str] = ""


# Provider presets for frontend
AI_PROVIDERS = {
    "openai": {"name": "OpenAI", "base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini"},
    "anthropic": {"name": "Anthropic Claude", "base_url": "https://api.anthropic.com", "model": "claude-sonnet-4-20250514"},
    "deepseek": {"name": "DeepSeek", "base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat"},
    "bailian": {"name": "阿里云百炼", "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1", "model": "qwen-plus"},
    "volcengine": {"name": "火山引擎豆包", "base_url": "https://ark.cn-beijing.volces.com/api/v3", "model": "doubao-pro-32k"},
}


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, db: Session = Depends(get_db)):
    """Render settings page."""
    ai_settings = get_ai_settings(db)
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "settings": ai_settings,
        "providers": AI_PROVIDERS,
    })


@router.get("/api/settings/ai")
async def get_ai_settings_api(db: Session = Depends(get_db)):
    """API: Get AI settings."""
    return get_ai_settings(db)


@router.put("/api/settings/ai")
async def update_ai_settings(settings: AISettingsUpdate, db: Session = Depends(get_db)):
    """API: Update AI settings."""
    init_default_settings(db)

    updates = {
        "ai_enabled": "true" if settings.ai_enabled else "false",
        "ai_provider": settings.ai_provider or "",
        "ai_api_key": settings.ai_api_key or "",
        "ai_base_url": settings.ai_base_url or "",
        "ai_model": settings.ai_model or "",
    }

    for key, value in updates.items():
        setting = db.query(Settings).filter(Settings.key == key).first()
        if setting:
            setting.value = value
        else:
            setting = Settings(key=key, value=value, description=AI_DEFAULTS.get(key, {}).get("description", ""))
            db.add(setting)

    db.commit()

    return {"success": True, "message": "AI配置已保存", "settings": get_ai_settings(db)}


@router.get("/api/settings/providers")
async def get_providers():
    """API: Get available AI provider presets."""
    return AI_PROVIDERS


class AITestRequest(BaseModel):
    ai_api_key: str
    ai_base_url: str
    ai_model: str


@router.post("/api/settings/ai/test")
async def test_ai_connection(req: AITestRequest):
    """API: Test AI connection with a simple prompt."""
    if not req.ai_api_key:
        return {"success": False, "message": "请填写API密钥"}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Try OpenAI-compatible endpoint first
            response = await client.post(
                f"{req.ai_base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {req.ai_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": req.ai_model,
                    "messages": [{"role": "user", "content": "Say 'OK' in one word."}],
                    "max_tokens": 10,
                },
            )

            if response.status_code == 200:
                return {"success": True, "message": f"连接成功！模型 {req.ai_model} 可用"}

            # If failed, try Anthropic endpoint
            if "anthropic" in req.ai_base_url:
                response = await client.post(
                    f"{req.ai_base_url}/v1/messages",
                    headers={
                        "x-api-key": req.ai_api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": req.ai_model,
                        "max_tokens": 10,
                        "messages": [{"role": "user", "content": "Say 'OK' in one word."}],
                    },
                )
                if response.status_code == 200:
                    return {"success": True, "message": f"连接成功！模型 {req.ai_model} 可用"}

            return {"success": False, "message": f"连接失败: HTTP {response.status_code}"}

    except httpx.ConnectError:
        return {"success": False, "message": "无法连接到API服务器，请检查API地址"}
    except httpx.TimeoutException:
        return {"success": False, "message": "连接超时，请检查网络或API地址"}
    except Exception as e:
        return {"success": False, "message": f"测试失败: {str(e)}"}
