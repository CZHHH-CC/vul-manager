import os
import socket
from dotenv import load_dotenv

load_dotenv()


def _is_postgres_available(host="localhost", port=5432, timeout=2):
    """Quick check if PostgreSQL port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _detect_database_url():
    """Detect database URL: env var > PostgreSQL localhost > SQLite fallback."""
    db_url = os.getenv("DATABASE_URL", "").strip()
    if db_url:
        return db_url

    # Try PostgreSQL on localhost (local dev without Docker)
    if _is_postgres_available():
        return "postgresql://postgres:vulpass@localhost:5432/vuldb"

    # SQLite fallback for local testing
    print("PostgreSQL not available, using SQLite fallback: vuldb.sqlite3")
    return "sqlite:///vuldb.sqlite3"


DATABASE_URL = _detect_database_url()

# ─── AI Provider Presets ─────────────────────────────────────────────────────
# Supports: openai, anthropic, deepseek, bailian, volcengine, custom
AI_PROVIDER = os.getenv("AI_PROVIDER", "").strip().lower()

_AI_PRESETS = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "model": "claude-sonnet-4-20250514",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
    },
    "bailian": {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "model": "qwen-plus",
    },
    "volcengine": {
        "base_url": "https://ark.cn-beijing.volces.com/api/v3",
        "model": "doubao-pro-32k",
    },
}

_preset = _AI_PRESETS.get(AI_PROVIDER, {})

AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_BASE_URL = os.getenv("AI_BASE_URL", _preset.get("base_url", "https://api.openai.com/v1"))
AI_MODEL = os.getenv("AI_MODEL", _preset.get("model", "gpt-4o-mini"))

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
