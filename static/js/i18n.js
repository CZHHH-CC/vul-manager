(function () {
  const translations = {
    "漏洞管理系统": "Vulnerability Manager",
    "仪表盘": "Dashboard",
    "漏洞列表": "Vulnerabilities",
    "上传数据": "Upload",
    "KPI 统计": "KPI",
    "导出报告": "Export Report",
    "设置": "Settings",
    "导出 Excel": "Export Excel",
    "补全 CVSS": "Enrich CVSS",
    "AI 分析": "AI Analysis",
    "生成修复方案": "Generate Fix Plans",
    "筛选条件": "Filters",
    "严重程度": "Severity",
    "状态": "Status",
    "服务器类型": "Server Type",
    "AI 分析": "AI Analysis",
    "修复方案": "Fix Plan",
    "全部": "All",
    "已分析": "Analyzed",
    "规则优先级": "Rule Priority",
    "待分析": "Pending",
    "已生成": "Generated",
    "未生成": "Not Generated",
    "应用": "Apply",
    "清除": "Clear",
    "搜索": "Search",
    "VIT 编号": "VIT",
    "CVE 编号": "CVE",
    "主机名": "Host",
    "类型": "Type",
    "优先级": "Priority",
    "创建时间": "Created",
    "操作": "Actions",
    "详情": "Details",
    "标记已修复": "Mark Fixed",
    "每页": "Per page",
    "条": "rows",
    "上一页": "Previous",
    "下一页": "Next",
    "检测到的组件": "Detected Components",
    "组件": "Component",
    "版本": "Version",
    "路径": "Path",
    "校验": "Check",
    "一致": "Matched",
    "版本差异": "Version Diff",
    "仅 AI": "AI Only",
    "基本信息": "Basic Info",
    "技术分析": "Technical Analysis",
    "风险评估": "Risk Assessment",
    "操作指南": "Guidance",
    "处置决策摘要": "Decision Summary",
    "快速操作": "Quick Actions",
    "AI 重新分析": "Re-analyze",
    "查看 NVD": "Open NVD",
    "变更历史": "Change History",
    "上传漏洞工单Excel": "Upload Vulnerability Excel",
    "拖拽 Excel 文件到此处，或点击选择文件": "Drop Excel here or click to choose",
    "支持 .xlsx 和 .xls 格式": "Supports .xlsx and .xls",
    "上传后自动 AI 分析并生成修复方案": "Auto analyze and generate fix plans after upload",
    "上传历史": "Upload History",
    "系统设置": "Settings",
    "AI智能分析": "AI Analysis",
    "AI服务商": "AI Provider",
    "API密钥": "API Key",
    "API地址": "API URL",
    "模型名称": "Model",
    "测试连接": "Test Connection",
    "保存设置": "Save",
    "配置指南": "Configuration Guide",
    "SNOW KPI": "SNOW KPI",
    "导出 PDF": "Export PDF",
    "未关闭漏洞": "Open Vulnerabilities",
    "超期未修复": "Overdue",
    "涉及 CVE": "CVEs",
    "受影响主机": "Affected Hosts",
    "时效分布": "Age Distribution",
    "负责团队": "Assignment Group"
  };

  const placeholderTranslations = {
    "搜索 VIT 编号 / CVE / 描述…": "Search VIT / CVE / description...",
    "CVE-XXXX-XXXXX": "CVE-XXXX-XXXXX",
    "主机名": "Host"
  };

  const reverse = Object.fromEntries(Object.entries(translations).map(([zh, en]) => [en, zh]));
  const reversePlaceholder = Object.fromEntries(Object.entries(placeholderTranslations).map(([zh, en]) => [en, zh]));
  const SKIP_TAGS = new Set(["SCRIPT", "STYLE", "CODE", "PRE", "TEXTAREA"]);

  function replaceTextNode(node, dict) {
    const raw = node.nodeValue;
    const trimmed = raw.trim();
    if (!trimmed) return;
    const replacement = dict[trimmed];
    if (!replacement) return;
    node.nodeValue = raw.replace(trimmed, replacement);
  }

  function walk(root, dict) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const parent = node.parentElement;
        if (!parent || SKIP_TAGS.has(parent.tagName) || parent.closest("[data-no-i18n]")) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach((node) => replaceTextNode(node, dict));
  }

  function translateAttrs(dict) {
    document.querySelectorAll("[placeholder]").forEach((el) => {
      const value = el.getAttribute("placeholder");
      if (dict[value]) el.setAttribute("placeholder", dict[value]);
    });
    document.querySelectorAll("[title]").forEach((el) => {
      const value = el.getAttribute("title");
      if (dict[value]) el.setAttribute("title", dict[value]);
    });
  }

  function applyLanguage(lang) {
    const toEnglish = lang === "en";
    walk(document.body, toEnglish ? translations : reverse);
    translateAttrs(toEnglish ? placeholderTranslations : reversePlaceholder);
    document.documentElement.lang = toEnglish ? "en" : "zh-CN";
    document.documentElement.dataset.lang = lang;
    const toggle = document.getElementById("langToggle");
    if (toggle) toggle.textContent = toEnglish ? "中文" : "EN";
  }

  document.addEventListener("DOMContentLoaded", () => {
    const saved = localStorage.getItem("vm.lang") || "zh";
    applyLanguage(saved);
    const toggle = document.getElementById("langToggle");
    if (toggle) {
      toggle.addEventListener("click", () => {
        const next = (localStorage.getItem("vm.lang") || "zh") === "zh" ? "en" : "zh";
        localStorage.setItem("vm.lang", next);
        applyLanguage(next);
      });
    }
  });
})();
