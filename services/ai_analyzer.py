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
受影响产品: {affected_products}
修复建议: {remediation_steps}
漏洞描述摘要: {description_summary}
检测逻辑原文: {detection_logic}

请用中文输出以下内容（JSON格式）:

1. "risk_summary": 2-3句话的风险评估摘要，说明该漏洞的危害程度和紧急性
2. "fix_priority": 修复优先级，取值为 P0（立即修复）、P1（3天内）、P2（1周内）、P3（1个月内）
3. "remediation_guide": 简洁的操作步骤指南，面向运维团队，不超过5条
4. "detected_components": 从"检测逻辑原文"中提取被检测到的组件列表，每个组件包含:
   - "name": 组件/软件名称（如 "Google Chrome", "kernel", "activemq"）
   - "version": 检测到的版本号（如 "144.0.7559.110"），没有则留空字符串
   - "path": 文件路径、注册表路径或包名（如 "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"），没有则留空字符串

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


SYSTEM_PROMPT = "你是网络安全漏洞分析专家，只输出JSON格式的结果。"


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
    return RISK_ANALYSIS_PROMPT.format(
        vit_number=vuln.vit_number,
        cve_id=vuln.cve_id or "N/A",
        hostname=vuln.hostname or "N/A",
        server_class=vuln.server_class or "N/A",
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
        return None


async def _call_openai_compatible(client: httpx.AsyncClient, user_prompt: str,
                                   base_url: str, api_key: str, model: str) -> Optional[str]:
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
            "max_tokens": 1000,
        },
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]


async def _call_anthropic(client: httpx.AsyncClient, user_prompt: str,
                           base_url: str, api_key: str, model: str) -> Optional[str]:
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
            "max_tokens": 1000,
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
                content = await _call_anthropic(client, user_prompt, base_url, api_key, model)
            else:
                content = await _call_openai_compatible(client, user_prompt, base_url, api_key, model)

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
