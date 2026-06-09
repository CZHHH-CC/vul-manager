# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Vulnerability Manager** is a FastAPI-based web application for managing, analyzing, and tracking software vulnerabilities across infrastructure. It integrates with multiple AI providers (OpenAI, Anthropic, DeepSeek, Alibaba Cloud, ByteDance) to provide automated vulnerability analysis and risk prioritization.

**Key Purpose**: Ingest vulnerability data from Excel/CSV files, parse technical details (CVSS scores, CVE IDs, exploit status), store in PostgreSQL, and provide dashboards + AI-powered risk analysis with remediation guidance.

## Architecture

### High-Level Structure

FastAPI Application (async) with three main layers:

1. **Routers (HTTP endpoints)**: dashboard (stats/charts), upload (Excel ingestion), vulns (CRUD/filtering), reports (export), settings (AI config)
2. **Services (Business Logic)**: excel_parser (parse HTML from cells), vul_service (query/filter/stats), ai_analyzer (AI API calls)
3. **Database (SQLAlchemy ORM)**: Models for Vulnerability, VulnAnalysis, VulnHistory, UploadLog, Settings; supports PostgreSQL or SQLite

### Database Schema

**Vulnerability** (main table with 1:1 and 1:N relationships):
- `vit_number` (unique): Ticket ID from source system
- `cve_id`: CVE identifier
- `hostname`, `ip_address`, `server_class`: Infrastructure details extracted from HTML
- `severity`, `severity_level` (1=Critical, 2=High, 3=Medium, 4=Low): Severity classification
- `state` (Open/Closed/In Progress): Current vulnerability status
- `raw_description`, `raw_recommendation`: Original HTML blobs from source system
- Timestamps: `opened_at`, `updated_at`, `created_at`, `last_import_at`

**VulnAnalysis** (1:1 relationship, cascade delete):
- CVSS metrics: `cvss_score`, `cvss_vector`
- CVSS components: `attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`
- Parsed data: `affected_products`, `remediation_steps`, `detection_logic`
- Exploit info: `exploit_status` (e.g., "Actively used", "weaponized, poc")
- AI-generated: `ai_risk_summary` (2-3 sentences), `ai_fix_priority` (P0-P3), `ai_remediation_guide` (5 steps)
- Metadata: `analyzed_at` (last AI analysis timestamp)

**VulnHistory** (1:N relationship, cascade delete):
- Tracks changes to `state`, `severity`, `assignment_group`, `short_description` over time
- Useful for audit compliance and change tracking

**UploadLog** & **Settings**:
- UploadLog: Records each Excel import with new/updated/error counts
- Settings: Key-value store for AI provider configuration (enabled/provider/api_key/base_url/model)

### Data Flow

1. **File Upload** -> Excel ingested via pandas, split into records
2. **HTML Parsing** -> Description/Recommendation columns contain HTML -> BeautifulSoup extracts CVSS, CVE, hostname, exploit status, etc.
3. **Upsert** -> Insert new or update existing vulnerabilities, track changes in history
4. **AI Analysis** (optional) -> Call AI API with vulnerability details -> get risk summary, priority (P0-P3), remediation guide
5. **Dashboard** -> Query statistics and display charts (severity distribution, top CVEs, trends)

### AI Integration

**Supported Providers**: openai, anthropic, deepseek, bailian (Alibaba Cloud), volcengine (ByteDance), custom

**Analysis Prompt** (in Chinese): Evaluates vulnerability against CVSS score, exploit status, affected products, and provides risk assessment

**Priority Logic** (P0-P3):
- P0: CVSS >= 9.0 OR actively exploited OR Critical severity
- P1: CVSS >= 7.0 OR has public PoC OR High severity
- P2: CVSS >= 4.0 OR Medium severity
- P3: Other

**Output**: JSON with `risk_summary`, `fix_priority`, `remediation_guide`

## Development Setup

### Prerequisites
- Python 3.12+
- PostgreSQL 13+ (or SQLite for local dev fallback)

### Local Development

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env  # Edit as needed
python -c "from db.database import engine, Base; from db.models import *; Base.metadata.create_all(bind=engine)"
python app.py  # http://localhost:8000 with auto-reload
```

### Docker Deployment

```bash
docker-compose up --build  # PostgreSQL + app
# Or: docker build -t vul-manager . && docker run -p 8000:8000 vul-manager
```

## Common Commands

### Running
```bash
# Development (auto-reload)
python app.py

# Production
uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
```

### Database Setup
```bash
# Create tables
python -c "from db.database import engine, Base; from db.models import *; Base.metadata.create_all(bind=engine)"

# Check connection
python -c "from config import DATABASE_URL; print(DATABASE_URL)"
```

### Testing
No formal test suite exists. To test manually:
1. Start server: `python app.py`
2. Browse to http://localhost:8000 or use curl:
   ```
   curl http://localhost:8000/api/dashboard/stats
   curl http://localhost:8000/api/vulns
   ```
3. Configure AI in Settings UI before testing AI features

### Environment Variables
- `DATABASE_URL`: PostgreSQL/SQLite connection (auto-detects localhost PostgreSQL, falls back to SQLite)
- `AI_API_KEY`: API key for chosen AI provider (required to enable AI analysis)
- `AI_PROVIDER`: Preset (openai/anthropic/deepseek/bailian/volcengine) or omit for custom
- `AI_BASE_URL`: Custom API endpoint (default: https://api.openai.com/v1)
- `AI_MODEL`: Model name (e.g., gpt-4o-mini, claude-sonnet-4-20250514)
- `HOST`, `PORT`: Server binding (default: 0.0.0.0:8000)

## Key Implementation Details

### Excel Parsing (services/excel_parser.py)

Expects columns: `Number` (VIT ID, required), `Vulnerability` (CVE), `Description` (HTML), `Recommendation` (HTML), `Vulnerability Severity`, `State`, `CI Name / Application Service`, `Class`, `Assignment group`, `Short description`, `Opened`, `Updated`.

**HTML Extraction Strategy**: BeautifulSoup searches for labeled div patterns:
- "CVSS Base Score" label -> next div = value
- Regex match "CVSS:3.1/AV:L/..." for vector
- "Attack Vector", "Attack Complexity", etc. labels -> sibling span = value
- "Exploit status" in bold -> extract status text (handles "weaponized, poc", "Actively used")
- "Affected Products", "Recommended Remediation", "Detection Logic" sections

Fields not found in HTML default to None or "N/A".

### Router Organization

- **dashboard.py**: HTML render + API endpoints (stats, severity dist, top CVEs, trends, state dist, class dist)
- **upload.py**: GET /upload (form), POST /api/upload (process Excel)
- **vulns.py**: List page, API list/detail, state update, AI analysis trigger, filtering
- **reports.py**: Excel export, weekly report JSON
- **settings.py**: HTML form + API endpoints (get/put AI settings, test connection, provider presets)

### AI Analysis Flow

1. Vulnerability submitted or imported
2. If AI enabled: `analyze_single_vuln()` retrieves AI settings from DB
3. Build prompt with vulnerability details
4. Async HTTP call to AI API (handles anthropic vs OpenAI format differences)
5. Parse JSON from response (strips markdown code blocks)
6. Store results or fallback to deterministic `compute_fix_priority()` if API fails

### Database Flexibility

- **SQLite**: Auto-enabled if PostgreSQL unavailable; uses WAL mode + foreign keys
- **PostgreSQL**: Preferred for production; no special config needed

## Code Patterns

### Async Patterns
- Routes use `async def` for concurrent handling
- AI calls via `httpx.AsyncClient` (non-blocking HTTP)
- Database calls are sync (SQLAlchemy ORM doesn't block in FastAPI context)

### Dependency Injection
- `db: Session = Depends(get_db)` injects database session
- Settings loaded on-demand via `get_ai_settings(db)`

### Error Handling
- Excel parsing catches per-row exceptions, increments error count
- AI API failures fall back to rule-based priority computation
- Missing HTML fields return None or "N/A"

### ORM Relationships
- `Vulnerability.analysis`: 1:1, cascade delete
- `Vulnerability.history`: 1:N, cascade delete
- Bidirectional via `back_populates`

## Important Notes for Future Development

1. **No automated tests**: Create pytest suite for critical features (Excel parsing, AI prompt generation)
2. **HTML parsing is brittle**: Future versions should validate HTML structure or switch to structured data (JSON)
3. **AI API costs**: Monitor token usage; consider adding request rate limiting for bulk analysis
4. **Chinese prompts**: All system prompts and analysis instructions are in Chinese; maintain consistency
5. **SQLite scalability**: Works for small deployments; use PostgreSQL for production
6. **Sequential AI analysis**: Current loop is sequential; consider `asyncio.gather()` for parallel API calls
7. **Change tracking**: VulnHistory is critical for audit compliance; do not truncate without review
8. **Provider presets**: Hardcoded in config.py and routers/settings.py; update both when adding new AI providers
