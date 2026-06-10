import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from db.database import engine, Base
from db.models import Settings, Vulnerability, VulnAnalysis, VulnHistory, UploadLog
from routers import upload, vulns, dashboard, reports, settings
from services.detection_parser import parse_detection_logic
from config import HOST, PORT

# Create tables
Base.metadata.create_all(bind=engine)

# Create app
app = FastAPI(title="漏洞管理系统", version="1.0.0")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include routers
app.include_router(dashboard.router)
app.include_router(upload.router)
app.include_router(vulns.router)
app.include_router(reports.router)
app.include_router(settings.router)


if __name__ == "__main__":
    print(f"Starting server at http://{HOST}:{PORT}")
    print(f"Dashboard: http://localhost:{PORT}/")
    print(f"Vuln List: http://localhost:{PORT}/vulns")
    print(f"Upload:    http://localhost:{PORT}/upload")
    print(f"Settings:  http://localhost:{PORT}/settings")
    uvicorn.run("app:app", host=HOST, port=PORT, reload=True)
