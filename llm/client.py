"""M4 大模型客户端：DeepSeek（OpenAI 兼容协议），带重试与降级。

三条工程约束：

1. **不把 key 写进配置**。config.yaml 只记环境变量名，运行时读取。
2. **大模型不可用不能拖垮检测链路**。小模型已经给出类别与置信度，LLM 只负责解释；
   接口失败时降级成一份模板报告，并显式标注"自动生成、未经模型润色"，
   而不是让上报接口超时、把探针一起拖死。
3. **超时与重试分开控制**。诊断走后台任务，超时给宽一点；看板助手是同步交互，给紧一点。
"""

from __future__ import annotations

import os
import time

import httpx

from llm.schema import Diagnosis, parse_diagnosis
from llm.prompts import ASSISTANT_SYSTEM, SYSTEM, build_assistant, build_diagnosis


class LLMUnavailable(RuntimeError):
    pass


class LLMClient:
    def __init__(self, cfg: dict):
        self.provider = cfg.get("provider", "deepseek")
        self.base_url = cfg.get("base_url", "https://api.deepseek.com").rstrip("/")
        self.model = cfg.get("model", "deepseek-chat")
        self.api_key_env = cfg.get("api_key_env", "DEEPSEEK_API_KEY")
        self.temperature = cfg.get("temperature", 0.2)
        self.timeout = cfg.get("timeout", 30)
        self.max_retries = cfg.get("max_retries", 2)
        self.max_tokens = cfg.get("max_tokens", 1500)
        self.calls = 0
        self.failures = 0

    @property
    def available(self) -> bool:
        return bool(os.environ.get(self.api_key_env))

    def _chat(self, system: str, user: str, timeout_s: float, json_mode: bool = False) -> str:
        key = os.environ.get(self.api_key_env)
        if not key:
            raise LLMUnavailable(f"环境变量 {self.api_key_env} 未设置")

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": False,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        last = None
        for attempt in range(self.max_retries + 1):
            try:
                with httpx.Client(timeout=timeout_s) as client:
                    resp = client.post(
                        f"{self.base_url}/chat/completions",
                        json=payload,
                        headers={"Authorization": f"Bearer {key}"},
                    )
                if resp.status_code == 200:
                    self.calls += 1
                    return resp.json()["choices"][0]["message"]["content"]
                last = f"HTTP {resp.status_code}: {resp.text[:200]}"
                # 4xx 除了 429 都是请求本身的问题，重试没有意义
                if 400 <= resp.status_code < 500 and resp.status_code != 429:
                    break
            except (httpx.HTTPError, ValueError) as exc:
                # ValueError 来自代理环境变量（如 ALL_PROXY 写成 socks://），构造 Client 时就抛，
                # 重试也不会好，直接收工交给调用方降级
                last = f"{type(exc).__name__}: {exc}"
                if isinstance(exc, ValueError):
                    break
            time.sleep(min(2 ** attempt * 0.5, 4.0))
        self.failures += 1
        raise LLMUnavailable(last or "未知错误")

    # ------------------------------------------------------------------ 诊断

    def diagnose(self, alert: dict, evidence, chunks) -> tuple[Diagnosis, int]:
        """返回 (报告, 耗时毫秒)。LLM 不可用时抛 LLMUnavailable，由调用方降级。"""
        t0 = time.perf_counter()
        text = self._chat(SYSTEM, build_diagnosis(alert, evidence, chunks), self.timeout, json_mode=True)
        elapsed = int((time.perf_counter() - t0) * 1000)
        return parse_diagnosis(text, alert.get("category", ""), alert.get("confidence", 0.0)), elapsed

    # ------------------------------------------------------------------ 看板助手

    def assistant(self, snapshot, history, question: str) -> str:
        """看板助手：自由对话，但"现在有多少"这类数字只能来自 snapshot。"""
        return self._chat(
            ASSISTANT_SYSTEM,
            build_assistant(snapshot, history, question),
            timeout_s=min(self.timeout, 30),
        )


def fallback_diagnosis(alert: dict, evidence) -> Diagnosis:
    """模板报告：LLM 不可用时也要让告警完整落库、看板不留空。"""
    category = alert.get("category", "未知类别")
    risk = alert.get("risk", "medium")
    by_rule = alert.get("source") == "rule"
    ev = []
    for item in evidence or []:
        if not isinstance(item, dict):
            continue
        if item.get("detail"):
            ev.append(str(item["detail"]))
        else:
            ev.append(f"{item.get('feature')} = {item.get('value')}（偏离 {item.get('z_score')} 个标准差）")

    if by_rule:
        verdict = (
            f"阈值规则判定为 {category}，实测值超出阈值 "
            f"{float(alert.get('confidence', 0)):.2f} 倍（规则不输出概率）。"
        )
    else:
        verdict = f"小模型判定为 {category}，置信度 {float(alert.get('confidence', 0)):.1%}。"
    return Diagnosis(
        summary=(
            f"探针 {alert.get('probe_id', '?')} 上报的流被{verdict}"
            "本报告由模板生成：大模型接口当前不可用，未经过模型润色。"
        ),
        risk=risk if risk in ("info", "low", "medium", "high", "critical") else "medium",
        evidence=ev or ["（无特征证据）"],
        actions=["先确认该源 IP 的资产归属与用途，再决定是否在边界设备做临时封禁。"],
        principle="（大模型不可用，未生成协议原理回顾。请参考 docs/ 中的协议说明。）",
        category=category,
        confidence=float(alert.get("confidence", 0.0)),
    )
