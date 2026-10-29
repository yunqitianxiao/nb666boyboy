"""M6 中心服务：接收探针上报 → 小模型推理 → 落库 → 触发大模型诊断。

启动::

    uvicorn center.main:app --host 0.0.0.0 --port 8000
    # 接口文档在 /docs

几个刻意的设计：

- **上报路径不做大模型调用**。诊断放在后台任务里跑，和探针上报解耦：
  LLM 慢或挂掉，检测链路照常工作，只是报告变成模板版并标注出来。
- **列序校验不宽容**。探针报上来的 feature_names 必须和训练时逐项相同，
  不匹配直接 400，而不是按名字重排——重排会把"缺列"悄悄变成"错位"。
- **告警与流分开存**。每条流都留档（含原始特征），只有非 BENIGN 的升级成告警。
  误报分析、召回率复盘都靠 flows 表，丢掉就没法复盘。
"""

from __future__ import annotations

import hmac
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from center.database import Store            # noqa: E402
from center.inference import BASE_RISK, Detector  # noqa: E402
from center.rules import RuleEngine, pick        # noqa: E402
from llm.client import LLMClient, LLMUnavailable, fallback_diagnosis  # noqa: E402
from llm.rag import Retriever                # noqa: E402
from llm.schema import validate              # noqa: E402
from settings import load_config             # noqa: E402

MAX_FLOWS_PER_REPORT = 2000


class FlowIn(BaseModel):
    key: str
    first_seen: float = 0.0
    last_seen: float = 0.0
    values: list[float]


class ReportIn(BaseModel):
    probe_id: str
    sent_at: float | None = None
    window: dict | None = None
    feature_names: list[str]
    flows: list[FlowIn] = Field(default_factory=list)


class DiagnoseIn(BaseModel):
    alert_id: int
    force: bool = False


class AssistantIn(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    # 历史由看板带着走：助手不落库，刷新页面等于开一段新对话
    history: list[dict] = Field(default_factory=list)


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = load_config(str(ROOT / "config.yaml"))
    app.state.cfg = cfg
    app.state.store = Store(str(ROOT / cfg["center"]["db_path"]))
    app.state.detector = Detector(
        str(ROOT / cfg["center"]["model_path"]), str(ROOT / cfg["center"]["schema_path"])
    )
    app.state.llm = LLMClient(cfg["llm"])
    app.state.retriever = Retriever(str(ROOT / cfg["rag"]["chunks_path"]))
    app.state.rules = RuleEngine()
    print(
        f"[中心] 模型已加载：{app.state.detector.selected_by or '未知选型口径'}；"
        f"大模型 {'可用' if app.state.llm.available else '未配置 key，将输出模板报告'}",
        flush=True,
    )
    yield


app = FastAPI(title="NetSentinel-LLM 中心服务", version="0.1.0", lifespan=lifespan)


def require_token(token: str | None) -> None:
    expected = app.state.cfg["center"]["token"]
    if not token or not hmac.compare_digest(str(token), str(expected)):
        raise HTTPException(status_code=401, detail="探针 token 无效")


# ---------------------------------------------------------------- 上报与推理


@app.post("/api/v1/report")
def report(body: ReportIn, background: BackgroundTasks, x_probe_token: str | None = Header(default=None)):
    require_token(x_probe_token)
    if len(body.flows) > MAX_FLOWS_PER_REPORT:
        raise HTTPException(413, f"单批流数超过上限 {MAX_FLOWS_PER_REPORT}")
    if not body.flows:
        return {"accepted": 0, "alerts": 0, "alert_ids": []}

    detector: Detector = app.state.detector
    # 列序不符直接拒收：宁可丢一批数据，也不能用错位的特征去推理
    try:
        detector.check_features(body.feature_names)
    except ValueError as exc:
        raise HTTPException(400, f"特征列不符：{exc}")

    store: Store = app.state.store
    rules: RuleEngine = app.state.rules
    values = [f.values for f in body.flows]
    preds = detector.predict_batch(values)

    alert_ids = []
    for flow, pred in zip(body.flows, preds):
        feats = dict(zip(body.feature_names, flow.values))
        store.add_flow(
            body.probe_id, flow.first_seen, flow.last_seen, flow.key,
            pred["category"], pred["confidence"],
            feats,   # 原始特征，复盘误报用
        )

        # 规则层与模型层并行跑。模型判正常而规则命中时照样出告警——
        # 那正是"数据集里没见过的采集形态"，也是规则层存在的理由。
        ts = flow.last_seen or flow.first_seen or time.time()
        hit = pick(rules.observe(body.probe_id, ts, flow.key, feats))

        if pred["category"] != "BENIGN":
            evidence = detector.top_features(flow.values, k=5)
            if hit is not None:
                evidence.append(hit.as_evidence())
            alert_ids.append(store.add_alert(
                body.probe_id, flow.key, pred["category"], pred["confidence"],
                pred["risk"], feats, evidence, source="model",
                rule=hit.rule if hit else None, proba=pred["proba"],
            ))
        elif hit is not None:
            # confidence 列在这里放的是"超出阈值多少倍"，不是概率（见 alerts.source）
            alert_ids.append(store.add_alert(
                body.probe_id, flow.key, hit.category, round(hit.strength, 3),
                BASE_RISK.get(hit.category, "medium"), feats, [hit.as_evidence()],
                source="rule", rule=hit.rule,
            ))
        else:
            continue
        background.add_task(diagnose_alert, alert_ids[-1])

    return {"accepted": len(body.flows), "alerts": len(alert_ids), "alert_ids": alert_ids}


def diagnose_alert(alert_id: int) -> None:
    """给一条告警生成报告。异常一律吞掉并落模板报告——后台任务里的异常没人接。"""
    store: Store = app.state.store
    alert = store.alert(alert_id)
    if not alert:
        return
    if store.report_for_alert(alert_id):
        return

    llm: LLMClient = app.state.llm
    evidence = alert.get("evidence") or []
    query = f"{alert['category']} {' '.join(str(e.get('feature', '')) for e in evidence[:3])}"
    try:
        chunks = app.state.retriever.retrieve(query, top_k=app.state.cfg["rag"]["top_k"])
    except Exception:
        chunks = []

    try:
        diagnosis, elapsed = llm.diagnose(alert, evidence, chunks)
    except LLMUnavailable as exc:
        diagnosis = fallback_diagnosis(alert, evidence)
        elapsed = 0
        print(f"[诊断] 大模型不可用（{exc}），告警 {alert_id} 落模板报告", flush=True)

    problems = validate(diagnosis)
    if problems:
        print(f"[诊断] 告警 {alert_id} 的报告缺字段：{problems}", flush=True)
    store.add_report(alert_id, diagnosis.to_markdown(), llm.model, elapsed)


# ---------------------------------------------------------------- 查询


@app.get("/api/v1/alerts")
def list_alerts(
    limit: int = 100,
    probe_id: str | None = None,
    category: str | None = None,
    since: float | None = None,
    x_probe_token: str | None = Header(default=None),
):
    require_token(x_probe_token)
    return {"alerts": app.state.store.alerts(limit, probe_id, category, since)}


@app.get("/api/v1/flows")
def list_flows(
    limit: int = 200,
    probe_id: str | None = None,
    since: float | None = None,
    x_probe_token: str | None = Header(default=None),
):
    """流水表数据源。默认 200 条、倒序，看板每 2 s 拉一次。"""
    require_token(x_probe_token)
    return {"flows": app.state.store.flows(min(limit, 2000), probe_id, since)}


@app.get("/api/v1/alerts/{alert_id}")
def get_alert(alert_id: int, x_probe_token: str | None = Header(default=None)):
    require_token(x_probe_token)
    alert = app.state.store.alert(alert_id)
    if not alert:
        raise HTTPException(404, "告警不存在")
    return {"alert": alert, "report": app.state.store.report_for_alert(alert_id)}


@app.post("/api/v1/diagnose")
def diagnose(body: DiagnoseIn, background: BackgroundTasks, x_probe_token: str | None = Header(default=None)):
    require_token(x_probe_token)
    alert = app.state.store.alert(body.alert_id)
    if not alert:
        raise HTTPException(404, "告警不存在")
    if body.force:
        # force 时先删旧报告再重跑；正常路径不会走到这里
        with app.state.store.connect() as conn:
            conn.execute("DELETE FROM reports WHERE alert_id=?", (body.alert_id,))
    elif app.state.store.report_for_alert(body.alert_id):
        return {"status": "exists", "report": app.state.store.report_for_alert(body.alert_id)}
    background.add_task(diagnose_alert, body.alert_id)
    return {"status": "queued", "alert_id": body.alert_id}


PROTO_NAME = {"6": "TCP", "17": "UDP", "1": "ICMP"}


def dashboard_snapshot(store: Store, rules: RuleEngine, since: float) -> list[str]:
    """把看板此刻的数字压成几行交给助手。

    没有这几行，助手回答"现在有多少告警"只能凭印象编；有了它就只需要照抄。
    这里只给数字，不给结论——结论留给模型，责任边界才清楚。
    """
    s = store.stats(since)
    span = max(1, int((time.time() - s["since"]) / 60))
    lines = [f"统计窗口：最近 {span} 分钟（数据库里只有这个窗口的数字）",
             f"流总数：{s['total_flows']}"]
    by_pred = s["by_prediction"]
    lines.append("小模型判定分布：" + ("，".join(
        f"{k} {v}" for k, v in sorted(by_pred.items(), key=lambda kv: -kv[1])) or "无"))
    by_proto = s["by_protocol"]
    lines.append("协议构成：" + ("，".join(
        f"{PROTO_NAME.get(k, '协议' + k)} {v}" for k, v in by_proto.items()) or "无"))

    alerts = s["alerts"]
    lines.append(f"告警数：{len(alerts)}")
    if alerts:
        by_cat: dict[str, int] = {}
        for a in alerts:
            by_cat[a["category"]] = by_cat.get(a["category"], 0) + 1
        lines.append("告警类别：" + "，".join(
            f"{k} {v}" for k, v in sorted(by_cat.items(), key=lambda kv: -kv[1])))
        lines.append("最近 5 条告警：" + "；".join(
            f"#{a['id']} {a['category']}（风险 {a['risk']}，"
            f"{time.strftime('%H:%M:%S', time.localtime(a['created_at']))}，"
            f"探针 {a['probe_id']}）" for a in alerts[:5]))

    rule_stats = rules.stats()
    if rule_stats.get("by_category"):
        lines.append("规则引擎命中的类别：" + "，".join(
            f"{k} {v}" for k, v in rule_stats["by_category"].items()))
    return lines


@app.post("/api/v1/assistant")
def assistant(body: AssistantIn, x_probe_token: str | None = Header(default=None)):
    """看板助手：自由对话，但数字只能来自刚刚拍下的看板快照。"""
    require_token(x_probe_token)
    snapshot = dashboard_snapshot(app.state.store, app.state.rules, time.time() - 3600)
    try:
        answer = app.state.llm.assistant(snapshot, body.history, body.question)
    except LLMUnavailable as exc:
        raise HTTPException(503, f"大模型不可用：{exc}")
    return {"answer": answer, "snapshot_lines": len(snapshot)}


@app.get("/api/v1/stats")
def stats(since: float | None = None, x_probe_token: str | None = Header(default=None)):
    require_token(x_probe_token)
    out = app.state.store.stats(since)
    detector: Detector = app.state.detector
    out["classes"] = detector.classes
    out["model"] = {"selected_by": detector.selected_by, "trained_at": detector.trained_at}
    out["llm"] = {
        "calls": app.state.llm.calls,
        "failures": app.state.llm.failures,
        "available": app.state.llm.available,
    }
    out["rules"] = app.state.rules.stats()
    return out


@app.get("/healthz")
def healthz():
    return {"ok": True, "ts": time.time()}
