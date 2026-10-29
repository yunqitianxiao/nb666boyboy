"""M4 诊断报告的固定输出结构。

为什么要卡死 schema：报告要同时喂给看板的五个固定板块、历史检索和导出。模型偶尔换个标题、
少一段，前端就得写一堆兜底；更要紧的是"风险等级"这一栏如果不枚举，模型会自己发明
"中高危"这种词，看板的颜色映射就静默失效。
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field

RISK_LEVELS = ["info", "low", "medium", "high", "critical"]

# 五个固定部分的键名与中文标题
SECTIONS = {
    "summary": "事件概述",
    "risk": "风险等级",
    "evidence": "证据链",
    "actions": "处置建议",
    "principle": "协议原理回顾",
}


@dataclass
class Diagnosis:
    summary: str = ""
    risk: str = "medium"
    evidence: list = field(default_factory=list)
    actions: list = field(default_factory=list)
    principle: str = ""
    category: str = ""
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    def to_markdown(self) -> str:
        risks = {"info": "提示", "low": "低", "medium": "中", "high": "高", "critical": "严重"}
        lines = [f"### {SECTIONS['summary']}", self.summary, ""]
        lines += [f"### {SECTIONS['risk']}", f"**{risks.get(self.risk, self.risk)}**", ""]
        lines += [f"### {SECTIONS['evidence']}"]
        lines += [f"- {e}" for e in self.evidence] or ["- （无）"]
        lines += ["", f"### {SECTIONS['actions']}"]
        lines += [f"{i}. {a}" for i, a in enumerate(self.actions, 1)] or ["1. （无）"]
        lines += ["", f"### {SECTIONS['principle']}", self.principle]
        return "\n".join(lines)


def _extract_json(text: str) -> dict:
    """模型经常把 JSON 包在 ```json 代码块里，或者前后带一句客套话。"""
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fenced:
        text = fenced.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        return json.loads(text[start : end + 1])
    raise ValueError(f"模型输出里找不到 JSON：{text[:200]}")


def parse_diagnosis(text: str, category: str = "", confidence: float = 0.0) -> Diagnosis:
    data = _extract_json(text)
    risk = str(data.get("risk", "medium")).strip().lower()
    if risk not in RISK_LEVELS:
        # 模型写"中高危"之类不在枚举里的值：归到最接近的档，别让看板拿不到颜色
        risk = _closest_risk(risk)
    return Diagnosis(
        summary=str(data.get("summary", "")).strip(),
        risk=risk,
        evidence=[str(x) for x in (data.get("evidence") or [])],
        actions=[str(x) for x in (data.get("actions") or [])],
        principle=str(data.get("principle", "")).strip(),
        category=category,
        confidence=float(confidence),
    )


def _closest_risk(text: str) -> str:
    table = [
        (("严重", "紧急", "critical", "severe"), "critical"),
        (("高", "high"), "high"),
        (("中", "medium", "moderate"), "medium"),
        (("低", "low"), "low"),
        (("提示", "info", "informational"), "info"),
    ]
    for keys, level in table:
        if any(k in text for k in keys):
            return level
    return "medium"


def validate(d: Diagnosis) -> list:
    """返回问题清单，空列表表示合格。看板在渲染前调用它。"""
    problems = []
    if not d.summary:
        problems.append("缺少事件概述")
    if d.risk not in RISK_LEVELS:
        problems.append(f"风险等级不在枚举内：{d.risk}")
    if not d.evidence:
        problems.append("缺少证据链")
    if not d.actions:
        problems.append("缺少处置建议")
    if not d.principle:
        problems.append("缺少协议原理回顾")
    return problems
