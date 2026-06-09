# 漏洞管理系统 (Vulnerability Manager)

基于 **FastAPI** 的漏洞管理与分析平台：导入 Excel 漏洞工单，自动解析 CVSS / CVE / 利用状态等技术细节，存入数据库，并提供仪表盘与 **AI 智能风险分析**（支持 OpenAI / Anthropic / DeepSeek / 阿里云百炼 / 火山引擎豆包）。

前端采用 [shadcn/ui](https://github.com/shadcn-ui/ui)（new-york 风格）设计语言，Tailwind CSS 在构建时编译为静态文件，**运行时不依赖任何外部 CDN**。

## 功能

- **仪表盘**：总量 / 严重度 / 修复率 / 超期统计，严重度·类型·状态分布图，趋势图，Top CVE
- **漏洞列表**：多维筛选 + 搜索 + 分页，批量 AI 分析，导出 Excel
- **漏洞详情**：基本信息、技术分析（CVSS 向量、受影响产品、修复建议、检测逻辑）、AI 分析、变更历史
- **Excel 上传**：拖拽上传，自动解析 HTML 字段并增量入库
- **AI 分析**：风险摘要、修复优先级（P0–P3）、操作指南
- **设置**：AI 服务商配置与连接测试

## 技术栈

FastAPI · SQLAlchemy · Jinja2 · pandas · BeautifulSoup · Chart.js · Tailwind CSS (shadcn/ui) · PostgreSQL / SQLite

## 快速开始（Docker，推荐）

```bash
docker compose up -d --build
# 访问 http://localhost:8000
```

Docker 构建会自动用 Tailwind 独立 CLI 编译前端 CSS，并启动 PostgreSQL + 应用。

## 本地开发

```bash
python -m venv venv
venv\Scripts\activate           # Windows
pip install -r requirements.txt
cp .env.example .env            # 按需修改

# 建表
python -c "from db.database import engine, Base; from db.models import *; Base.metadata.create_all(bind=engine)"

python app.py                   # http://localhost:8000
```

### 修改前端样式后重新编译 CSS

模板中新增/修改 Tailwind class 后，需重新编译 `static/css/app.css`：

```bash
# 下载独立 CLI（一次性）：https://github.com/tailwindlabs/tailwindcss/releases
./tailwindcss -c tailwind.config.js -i static/css/tailwind-input.css -o static/css/app.css --minify
```

（使用 Docker 构建时此步骤会自动完成。）

## 环境变量

| 变量 | 说明 |
|------|------|
| `DATABASE_URL` | 数据库连接，未配置时回退到 SQLite |
| `AI_API_KEY` | AI 服务商 API Key（启用 AI 分析所需） |
| `AI_PROVIDER` | `openai` / `anthropic` / `deepseek` / `bailian` / `volcengine`，留空为自定义 |
| `AI_BASE_URL` | API 地址 |
| `AI_MODEL` | 模型名（如 `gpt-4o-mini`） |
| `HOST` / `PORT` | 服务绑定，默认 `0.0.0.0:8000` |

## 许可证

仅供内部使用。
