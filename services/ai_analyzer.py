import asyncio
import json
from datetime import datetime
from typing import Optional
import httpx
from sqlalchemy.orm import Session
from db.models import Vulnerability, VulnAnalysis


RISK_ANALYSIS_PROMPT = """你是一位资深的网络安全漏洞分析专家。请根据以下漏洞信息，生成简洁的风险分析报告。

漏洞编号: {vit_number}
CVE编号: {cve_id}
主机名: {hostname}
服务器类型: {server_class}
严重程度: {severity}
CVSS评分: {cvss_score}
CVSS向量: {cvss_vector}
攻击向量: {attack_vector}
攻击复杂度: {attack_complexity}
所需权限: {privileges_required}
利用状态: {exploit_status}
操作系统: {os_version}
受影响产品: {affected_products}
修复建议: {remediation_steps}
漏洞描述摘要: {description_summary}
检测逻辑原文: {detection_logic}

请用中文输出以下内容（JSON格式）:

1. "risk_summary": 2-3句话的风险评估摘要，说明该漏洞的危害程度和紧急性
2. "fix_priority": 修复优先级，取值为 P0（立即修复）、P1（3天内）、P2（1周内）、P3（1个月内）
3. "remediation_guide": 面向安全/运维负责人的【处置决策摘要】，2-3 条，帮助快速判断如何处置。注意：这里只讲方向，【不要写 apt/yum 等具体命令行】——具体可执行命令由单独的"修复方案"功能提供，避免重复:
   - 第1条 根因：结合"检测逻辑原文/受影响产品/操作系统"，一句话说明本机命中的具体组件及版本；若该版本已 EOL（停止维护，如 Node.js 12/14、Python 2、CentOS 6/7、Ubuntu 16.04 等），必须点明"已停止维护、不再获得安全补丁"
   - 第2条 处置方向：升级到受支持的版本（给出目标大版本），或（若暂时无法升级）可采取的临时缓解方向；只说方向与目标，不写命令行
   - 第3条 紧急度：结合修复优先级与利用状态，给出建议处置时限（如"已被野外利用，建议 24 小时内处置"）
   - 信息不足以确定具体版本时，如实说明"需进一步确认 XX"，不要编造
4. "detected_components": 从"检测逻辑原文"中提取被检测到的组件列表，每个组件包含:
   - "name": 组件/软件名称（如 "Google Chrome", "kernel", "activemq"）
   - "version": 检测到的版本号（如 "144.0.7559.110"），没有则留空字符串
   - "path": 文件路径、注册表路径或包名（如 "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"），没有则留空字符串

5. "os_version": 从漏洞描述和检测逻辑中提取操作系统版本信息（如 "Ubuntu 22.04", "Windows Server 2019", "RHEL 9.2"），无法确定则留空字符串

提取规则:
- 只提取实际检测到的组件，忽略检测条件描述
- 版本号只保留数字和点，去掉 "version:" 等前缀
- 如果原文为空或无意义，detected_components 返回空数组 []

评分参考:
- P0: CVSS>=9.0 或 被积极利用(Actively used) 或 Critical级别
- P1: CVSS>=7.0 或 有公开PoC(weaponized, poc) 或 High级别
- P2: CVSS>=4.0 或 Medium级别
- P3: 其他

请直接输出JSON，不要包含其他文字。"""


FIX_PLAN_PROMPT = """你是一位资深的网络安全运维专家。请根据以下漏洞信息，生成详细的修复方案。

CVE编号: {cve_id}
操作系统: {os_version}
服务器类型: {server_class}
检测到的组件: {detected_components}
漏洞描述摘要: {description_summary}
现有修复建议: {remediation_steps}

请用中文输出详细的修复方案（JSON格式）:

1. "fix_summary": 一句话说明修复目标
2. "prerequisites": 修复前的准备工作（如备份、维护窗口等）
3. "fix_steps": 详细的修复步骤列表，每步包含:
   - "step": 步骤编号
   - "action": 操作说明
   - "command": 具体的修复命令（根据操作系统类型给出对应命令，如 apt/yum/winget/chrome 更新命令等）
   - "expected_output": 命令执行后的预期输出
4. "verification": 修复验证步骤，包含:
   - "commands": 验证命令列表
   - "expected_results": 验证通过的预期结果
   - "success_indicators": 判断修复成功的具体指标
5. "rollback": 回滚方案（如果修复失败如何恢复）

要求:
- 命令必须具体可执行，不要用占位符
- 根据操作系统类型给出对应的包管理器命令
- 如果是软件组件漏洞，给出升级到安全版本的具体命令
- 验证步骤必须明确可判断

请直接输出JSON，不要包含其他文字。"""


REVIEW_FIX_PLAN_PROMPT = """你是一位资深的网络安全架构师。请审查并【直接修正】以下修复方案，使其对该主机正确、安全、可执行。

CVE编号: {cve_id}
操作系统: {os_version}
待审查的修复方案:
{fix_plan}

请重点检查并修正以下常见错误:
- 漏洞所属产品与目标主机是否匹配（例如 Office 漏洞但主机是未装 Office 的服务器；某 KB 补丁不适用于该 Windows 版本）
- 命令是否适配该操作系统、工具用法是否正确（如 Windows 的 .msu 应用 wusa 而非 msiexec；非内置 PowerShell cmdlet 需先安装模块）
- 命令是否具体可执行、是否含危险操作
- 验证与回滚是否可靠

请直接输出【修正后的完整修复方案】（JSON格式，不要包含其他文字）:

1. "risk_level": 修复操作本身的风险等级（"低"/"中"/"高"）
2. "corrections": 你对原方案做出的修正列表，每条简述"原问题 → 如何改"；若原方案无需修改则返回 []
3. "residual_risks": 仍需人工确认或注意的事项列表（如"需先确认该主机是否安装了 XX"）；无则返回 []
4. "fix_summary": 一句话修复目标
5. "prerequisites": 修复前准备工作（字符串）
6. "fix_steps": 修正后的步骤列表，每步含 "step" / "action" / "command" / "expected_output"
7. "verification": {{ "commands": [...], "success_indicators": "..." }}
8. "rollback": 回滚方案（必须是字符串，不要用对象）

要求: 命令必须具体可执行且适配上述操作系统；若发现漏洞与主机不匹配，应在 corrections 中说明并把方案改为"先确认适用性"的安全步骤。"""


SYSTEM_PROMPT = "你是网络安全漏洞分析专家，只输出JSON格式的结果。"


def extract_os_version(raw_desc: str) -> str:
    """Extract OS version from raw description HTML using regex."""
    if not raw_desc:
        return ""

    import re
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(str(raw_desc), "lxml")
    text = soup.get_text(separator=" ", strip=True)

    # Windows Server versions
    m = re.search(r"Windows Server\s*(\d{4})", text)
    if m:
        return f"Windows Server {m.group(1)}"

    # Linux distributions
    patterns = [
        (r"Ubuntu\s+(\d+\.\d+)", "Ubuntu"),
        (r"RHEL\s+(\d+\.\d+)", "RHEL"),
        (r"Red Hat Enterprise Linux\s+(\d+\.\d+)", "RHEL"),
        (r"CentOS\s+(\d+)", "CentOS"),
        (r"Debian\s+(\d+)", "Debian"),
        (r"SUSE\s+(\d+)", "SUSE"),
        (r"Amazon Linux\s+(\d+)", "Amazon Linux"),
    ]
    for pattern, name in patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            return f"{name} {m.group(1)}"

    # Fallback: check for generic OS mentions
    if "Windows" in text:
        return "Windows"
    if "Linux" in text or "Ubuntu" in text or "RHEL" in text:
        return "Linux"

    return ""


def get_description_summary(raw_desc: str, max_len: int = 500) -> str:
    """Extract a short text summary from HTML description."""
    if not raw_desc:
        return "N/A"
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(str(raw_desc), "lxml")
    text = soup.get_text(separator=" ", strip=True)
    for marker in ["Vulnerability Description", "Summary"]:
        idx = text.find(marker)
        if idx >= 0:
            text = text[idx + len(marker):]
            break
    return text[:max_len].strip()


def _build_user_prompt(vuln: Vulnerability, analysis) -> str:
    """Build the user prompt for AI analysis."""
    desc_summary = get_description_summary(vuln.raw_description)
    detection_logic = (analysis.detection_logic[:800] if analysis and analysis.detection_logic else "N/A")
    os_version = (analysis.os_version if analysis and analysis.os_version else "") \
        or extract_os_version(vuln.raw_description) or "N/A"
    return RISK_ANALYSIS_PROMPT.format(
        vit_number=vuln.vit_number,
        cve_id=vuln.cve_id or "N/A",
        hostname=vuln.hostname or "N/A",
        server_class=vuln.server_class or "N/A",
        os_version=os_version,
        severity=vuln.severity or "N/A",
        cvss_score=analysis.cvss_score if analysis else "N/A",
        cvss_vector=analysis.cvss_vector if analysis else "N/A",
        attack_vector=analysis.attack_vector if analysis else "N/A",
        attack_complexity=analysis.attack_complexity if analysis else "N/A",
        privileges_required=analysis.privileges_required if analysis else "N/A",
        exploit_status=analysis.exploit_status if analysis else "N/A",
        affected_products=(analysis.affected_products[:300] if analysis and analysis.affected_products else "N/A"),
        remediation_steps=(analysis.remediation_steps[:500] if analysis and analysis.remediation_steps else "N/A"),
        description_summary=desc_summary,
        detection_logic=detection_logic,
    )


def _parse_ai_response(content: str) -> Optional[dict]:
    """Parse JSON from AI response, handling markdown code blocks."""
    content = content.strip()
    if "```json" in content:
        content = content.split("```json")[1].split("```")[0].strip()
    elif "```" in content:
        content = content.split("```")[1].split("```")[0].strip()
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    # Fallback: salvage the outermost {...} object (handles trailing prose / minor truncation)
    start = content.find("{")
    end = content.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(content[start:end + 1])
        except json.JSONDecodeError:
            return None
    return None


async def _call_openai_compatible(client: httpx.AsyncClient, user_prompt: str,
                                   base_url: str, api_key: str, model: str,
                                   max_tokens: int = 1500) -> Optional[str]:
    """Call OpenAI-compatible API (OpenAI, DeepSeek, 百炼, 火山, etc.)."""
    response = await client.post(
        f"{base_url}/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.3,
            "max_tokens": max_tokens,
        },
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]


async def _call_anthropic(client: httpx.AsyncClient, user_prompt: str,
                           base_url: str, api_key: str, model: str,
                           max_tokens: int = 1500) -> Optional[str]:
    """Call Anthropic Claude API."""
    response = await client.post(
        f"{base_url}/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": max_tokens,
            "system": SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.3,
        },
    )
    response.raise_for_status()
    data = response.json()
    return data["content"][0]["text"]


async def analyze_single_vuln(vuln: Vulnerability, ai_settings: dict) -> Optional[dict]:
    """Call AI API to analyze a single vulnerability using provided settings."""
    if not ai_settings.get("ai_enabled") or not ai_settings.get("ai_api_key"):
        return None

    api_key = ai_settings["ai_api_key"]
    base_url = ai_settings.get("ai_base_url", "https://api.openai.com/v1")
    model = ai_settings.get("ai_model", "gpt-4o-mini")
    provider = ai_settings.get("ai_provider", "")

    user_prompt = _build_user_prompt(vuln, vuln.analysis)

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            if provider == "anthropic":
                content = await _call_anthropic(client, user_prompt, base_url, api_key, model, max_tokens=2000)
            else:
                content = await _call_openai_compatible(client, user_prompt, base_url, api_key, model, max_tokens=2000)

            if content:
                return _parse_ai_response(content)
            return None

    except Exception as e:
        print(f"AI analysis failed for {vuln.vit_number}: {e}")
        return None


def compute_fix_priority(vuln: Vulnerability) -> str:
    """Compute fix priority based on severity and exploit status (no AI needed)."""
    analysis = vuln.analysis
    if not analysis:
        return "P2"

    severity = (vuln.severity or "").lower()
    exploit = (analysis.exploit_status or "").lower()
    cvss = analysis.cvss_score or 0

    if cvss >= 9.0 or "actively" in exploit or "critical" in severity:
        return "P0"
    elif cvss >= 7.0 or "weaponized" in exploit or "poc" in exploit or "high" in severity:
        return "P1"
    elif cvss >= 4.0 or "medium" in severity:
        return "P2"
    else:
        return "P3"


async def analyze_vulnerabilities(db: Session, ai_settings: dict,
                                   vit_numbers: Optional[list[str]] = None) -> dict:
    """Analyze vulnerabilities with AI concurrently. If vit_numbers is None, analyze all unanalyzed."""
    if not ai_settings.get("ai_enabled") or not ai_settings.get("ai_api_key"):
        return {"error": "AI功能未启用或未配置API密钥", "analyzed": 0}

    query = db.query(Vulnerability)
    if vit_numbers:
        query = query.filter(Vulnerability.vit_number.in_(vit_numbers))
    else:
        query = query.filter(
            ~Vulnerability.analysis.has(VulnAnalysis.ai_risk_summary.isnot(None))
        )

    vulns = query.all()
    if not vulns:
        return {"analyzed": 0, "errors": 0, "total": 0}

    analyzed = 0
    errors = 0
    semaphore = asyncio.Semaphore(10)  # 10 concurrent requests

    async def _analyze_one(vuln):
        nonlocal analyzed, errors
        async with semaphore:
            result = await analyze_single_vuln(vuln, ai_settings)

        if result:
            if not vuln.analysis:
                analysis = VulnAnalysis(vulnerability_id=vuln.id)
                db.add(analysis)
                db.flush()
                vuln.analysis = analysis

            vuln.analysis.ai_risk_summary = result.get("risk_summary")
            vuln.analysis.ai_fix_priority = result.get("fix_priority")
            vuln.analysis.ai_remediation_guide = result.get("remediation_guide")
            components = result.get("detected_components")
            if components:
                import json as _json
                vuln.analysis.detected_components = _json.dumps(components, ensure_ascii=False)
            # Save OS version (prefer regex extraction from description)
            os_ver = extract_os_version(vuln.raw_description)
            # If regex found a specific version, use it; otherwise use AI result
            if not os_ver or os_ver in ("Windows", "Linux"):
                ai_os = result.get("os_version", "")
                if ai_os and ai_os not in ("Windows", "Linux"):
                    os_ver = ai_os
            # If still generic, try to get version from server_class context
            if os_ver in ("Windows", "Linux") and vuln.server_class:
                sc = vuln.server_class.lower()
                if "windows" in sc and os_ver == "Windows":
                    os_ver = "Windows Server"
                elif "linux" in sc and os_ver == "Linux":
                    os_ver = "Linux Server"
            if os_ver:
                vuln.analysis.os_version = os_ver
            vuln.analysis.analyzed_at = datetime.utcnow()
            analyzed += 1
        else:
            if vuln.analysis and not vuln.analysis.ai_fix_priority:
                vuln.analysis.ai_fix_priority = compute_fix_priority(vuln)
            errors += 1

    # Run in batches of 50 to avoid transaction timeout
    batch_size = 50
    for i in range(0, len(vulns), batch_size):
        batch = vulns[i:i + batch_size]
        await asyncio.gather(*[_analyze_one(v) for v in batch])
        db.commit()

    return {"analyzed": analyzed, "errors": errors, "total": len(vulns)}


async def generate_fix_plan(vuln: Vulnerability, ai_settings: dict) -> Optional[dict]:
    """Generate a detailed fix plan with commands and verification steps."""
    if not ai_settings.get("ai_enabled") or not ai_settings.get("ai_api_key"):
        return None

    analysis = vuln.analysis
    detected_components = "N/A"
    if analysis and analysis.detected_components:
        detected_components = analysis.detected_components

    os_version = "N/A"
    if analysis and analysis.os_version:
        os_version = analysis.os_version

    desc_summary = get_description_summary(vuln.raw_description)

    user_prompt = FIX_PLAN_PROMPT.format(
        cve_id=vuln.cve_id or "N/A",
        os_version=os_version,
        server_class=vuln.server_class or "N/A",
        detected_components=detected_components,
        description_summary=desc_summary,
        remediation_steps=(analysis.remediation_steps[:500] if analysis and analysis.remediation_steps else "N/A"),
    )

    try:
        async with httpx.AsyncClient(timeout=90.0) as client:
            if ai_settings.get("ai_provider") == "anthropic":
                content = await _call_anthropic(client, user_prompt,
                    ai_settings.get("ai_base_url", ""), ai_settings["ai_api_key"],
                    ai_settings.get("ai_model", ""), max_tokens=4000)
            else:
                content = await _call_openai_compatible(client, user_prompt,
                    ai_settings.get("ai_base_url", ""), ai_settings["ai_api_key"],
                    ai_settings.get("ai_model", ""), max_tokens=4000)

            if content:
                return _parse_ai_response(content)
        return None
    except Exception as e:
        print(f"Fix plan generation failed for {vuln.vit_number}: {e}")
        return None


async def review_fix_plan(vuln: Vulnerability, fix_plan: dict, ai_settings: dict) -> Optional[dict]:
    """AI review of the generated fix plan."""
    if not ai_settings.get("ai_enabled") or not ai_settings.get("ai_api_key"):
        return None

    analysis = vuln.analysis
    os_version = analysis.os_version if analysis else "N/A"

    user_prompt = REVIEW_FIX_PLAN_PROMPT.format(
        cve_id=vuln.cve_id or "N/A",
        os_version=os_version,
        fix_plan=json.dumps(fix_plan, ensure_ascii=False, indent=2),
    )

    try:
        async with httpx.AsyncClient(timeout=90.0) as client:
            if ai_settings.get("ai_provider") == "anthropic":
                content = await _call_anthropic(client, user_prompt,
                    ai_settings.get("ai_base_url", ""), ai_settings["ai_api_key"],
                    ai_settings.get("ai_model", ""), max_tokens=3000)
            else:
                content = await _call_openai_compatible(client, user_prompt,
                    ai_settings.get("ai_base_url", ""), ai_settings["ai_api_key"],
                    ai_settings.get("ai_model", ""), max_tokens=3000)

            if content:
                return _parse_ai_response(content)
        return None
    except Exception as e:
        print(f"Fix plan review failed for {vuln.vit_number}: {e}")
        return None


async def _build_reviewed_plan(vuln: Vulnerability, ai_settings: dict):
    """Generate a fix plan, then review-and-correct it into a single final plan.

    Returns (final_plan, meta) where meta = {risk_level, corrections, residual_risks},
    or (None, None) on failure.
    """
    draft = await generate_fix_plan(vuln, ai_settings)
    if not draft:
        return None, None

    review = await review_fix_plan(vuln, draft, ai_settings)
    if review and (review.get("fix_steps") or review.get("fix_summary")):
        final_plan = {
            "fix_summary": review.get("fix_summary") or draft.get("fix_summary"),
            "prerequisites": review.get("prerequisites") or draft.get("prerequisites"),
            "fix_steps": review.get("fix_steps") or draft.get("fix_steps"),
            "verification": review.get("verification") or draft.get("verification"),
            "rollback": review.get("rollback") or draft.get("rollback"),
        }
        meta = {
            "reviewed": True,
            "risk_level": review.get("risk_level"),
            "corrections": review.get("corrections") or [],
            "residual_risks": review.get("residual_risks") or [],
        }
    else:
        # Review failed; fall back to the draft (still usable)
        final_plan = draft
        meta = {"reviewed": False, "risk_level": None, "corrections": [], "residual_risks": []}
    return final_plan, meta


async def generate_and_review_fix_plan(db: Session, vit_number: str, ai_settings: dict) -> dict:
    """Generate a fix plan and review-correct it into a single validated plan."""
    vuln = db.query(Vulnerability).filter(Vulnerability.vit_number == vit_number).first()
    if not vuln:
        return {"error": "漏洞不存在"}
    if not vuln.analysis:
        return {"error": "请先执行 AI 分析"}

    final_plan, meta = await _build_reviewed_plan(vuln, ai_settings)
    if not final_plan:
        return {"error": "修复方案生成失败"}

    vuln.analysis.ai_fix_plan = json.dumps(final_plan, ensure_ascii=False)
    vuln.analysis.ai_fix_plan_review = json.dumps(meta, ensure_ascii=False)
    db.commit()

    return {"success": True, "fix_plan": final_plan, "review": meta}


async def generate_fix_plans_bulk(db: Session, ai_settings: dict,
                                  only_missing: bool = True) -> dict:
    """Generate + review fix plans for vulnerabilities that have an analysis.

    Heavy operation (2 API calls per vuln); intended to run as a background task.
    """
    if not ai_settings.get("ai_enabled") or not ai_settings.get("ai_api_key"):
        return {"generated": 0, "errors": 0, "total": 0}

    candidates = [
        v for v in db.query(Vulnerability).all()
        if v.analysis and (not only_missing or not v.analysis.ai_fix_plan)
    ]
    if not candidates:
        return {"generated": 0, "errors": 0, "total": 0}

    generated = 0
    errors = 0
    semaphore = asyncio.Semaphore(3)  # fix plans are heavy; keep concurrency low

    async def _one(vuln):
        nonlocal generated, errors
        async with semaphore:
            final_plan, meta = await _build_reviewed_plan(vuln, ai_settings)
        if not final_plan:
            errors += 1
            return
        vuln.analysis.ai_fix_plan = json.dumps(final_plan, ensure_ascii=False)
        vuln.analysis.ai_fix_plan_review = json.dumps(meta, ensure_ascii=False)
        generated += 1

    batch_size = 30
    for i in range(0, len(candidates), batch_size):
        await asyncio.gather(*[_one(v) for v in candidates[i:i + batch_size]])
        db.commit()

    return {"generated": generated, "errors": errors, "total": len(candidates)}
