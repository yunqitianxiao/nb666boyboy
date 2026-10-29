"""M4 提示词：把「小模型的判定 + 特征证据 + 检索到的协议知识」拼成一次诊断请求。

三条硬约束写进系统提示词，因为它们是这个项目最容易被模型违反的三件事：

1. **不许改判**。小模型已经给了类别，LLM 的职责是解释和给处置建议，不是重新分类。
   放任它改判，就等于把一个可评测的分类器换成一个不可复现的接口。
2. **只准引用给定的证据**。模型很容易把"典型 DDoS 的表现"当成"本次流量的表现"来写，
   报告读起来很专业，但那是编的。
3. **必须回到协议层**。这是计算机网络课设，评审最关心的恰恰是"你懂不懂协议"。
"""

from __future__ import annotations

import json

SYSTEM = """你是一名网络安全分析工程师，正在为一个小型入侵检测系统写中文事件报告。

铁律：
1. 攻击类别由上游分类模型给出，你不要改判，也不要给出你自己的类别概率。
2. 证据链只能引用用户消息里提供的数据。禁止编造报文内容、IP、时间戳或流量数值。
   如果证据不足以支撑某句话，就不写那句话。
3. 处置建议要具体可执行（改什么配置、查哪台主机、封哪个方向），不要写"加强防护"这种空话。
4. 协议原理回顾要讲清楚这类攻击利用的协议机制（握手、状态机、字段语义），
   面向的是刚学完计算机网络课程的读者。
5. 只输出一个 JSON 对象，不要输出解释文字或 Markdown 代码块以外的内容。

JSON 结构：
{
  "summary": "两三句话说明发生了什么",
  "risk": "info|low|medium|high|critical 五选一",
  "evidence": ["引用具体特征值的一条证据", "..."],
  "actions": ["具体处置动作", "..."],
  "principle": "协议原理回顾，一段话"
}"""


ASSISTANT_SYSTEM = """你是 NetSentinel-LLM 网络流量分析系统的看板助手，正在和其他看板使用者对话。

对方多半刚学完《计算机网络》：术语可以照常用，但第一次出现时补一句白话。

规则：
1. 【当前看板快照】是数据库里此刻的真实数字，涉及"现在有多少""哪类最多"这类问题
   只能引用它。快照里没有的统计就说"看板上没有这项"，不要估算、不要补全。
2. 协议原理、攻击手法、处置思路可以按通用知识回答；一旦落到具体数值和现场状态，
   就必须来自快照或之前的对话。
3. 禁止编造报文内容、IP、时间戳。举例子时明确说"举个例子"。
4. 直接说人话，不要输出 JSON，不要用标题层级堆结构。短问题短回答，一般不超过 300 字。
5. 对方问处置时，给可执行的动作（查哪台主机、看哪个字段、改哪条规则），
   不要写"加强防护"这种空话。"""


def _fmt_snapshot(snapshot) -> str:
    lines = [f"- {item}" for item in snapshot or []]
    return "\n".join(lines) or "- （暂时取不到看板数据）"


def build_assistant(snapshot, history, question: str) -> str:
    turns = []
    for msg in (history or [])[-12:]:
        role = msg.get("role")
        who = "你" if role == "assistant" else "对方"
        turns.append(f"{who}：{msg.get('content', '')}")
    convo = "\n".join(turns) or "（这是第一句）"
    return f"""【当前看板快照】
{_fmt_snapshot(snapshot)}

【之前的对话】
{convo}

对方：{question}"""


def _fmt_evidence(evidence) -> str:
    lines = []
    for item in evidence or []:
        if isinstance(item, dict):
            if item.get("detail"):
                # 规则命中的证据自带措辞，z 分数对它们没有意义
                lines.append(f"- {item['detail']}")
                continue
            z = item.get("z_score")
            lines.append(
                f"- {item.get('feature')} = {item.get('value')}"
                + (f"（偏离训练分布 {z} 个标准差）" if z is not None else "")
            )
        else:
            lines.append(f"- {item}")
    return "\n".join(lines) or "- （无）"


def _fmt_proba(proba) -> str:
    if not proba:
        return "（无）"
    ordered = sorted(proba.items(), key=lambda kv: -kv[1])[:3]
    return "，".join(f"{k} {v:.1%}" for k, v in ordered)


def _fmt_chunks(chunks) -> str:
    if not chunks:
        return "（未检索到相关资料）"
    return "\n\n".join(f"[{c.get('title', '资料')}] {c.get('text', '')}" for c in chunks)


def build_diagnosis(alert: dict, evidence, chunks) -> str:
    if alert.get("source") == "rule":
        # 规则告警没有"各类概率"，也不能把 strength 说成置信度
        head = (
            f"【命中来源】阈值规则（确定性判据，不是分类模型）\n"
            f"【命中类别】{alert.get('category')}　"
            f"超出阈值 {float(alert.get('confidence', 0)):.2f} 倍　风险等级 {alert.get('risk')}"
        )
    else:
        head = (
            f"【分类结果】{alert.get('category')}　"
            f"置信度 {float(alert.get('confidence', 0)):.1%}　风险等级 {alert.get('risk')}\n"
            f"【各类概率】{_fmt_proba(alert.get('proba'))}"
        )
    return f"""请为下面这条告警写诊断报告。

{head}
【探针】{alert.get('probe_id')}　【流标识】{alert.get('flow_key')}

【该流偏离训练分布最明显的特征】
{_fmt_evidence(evidence)}

【检索到的协议资料（供原理回顾参考，引用时不必标注来源）】
{_fmt_chunks(chunks)}

只输出 JSON。"""


def build_prompt_preview(alert: dict, evidence, chunks) -> str:
    """把完整提示词拼出来，便于测试与答辩时展示。"""
    return json.dumps(
        {"system": SYSTEM, "user": build_diagnosis(alert, evidence, chunks)},
        ensure_ascii=False,
        indent=2,
    )
