"""M5 可视化看板：实时流量、告警列表、LLM 诊断报告与看板助手。

启动::

    streamlit run dashboard/app.py

配色说明：分类色按固定槽位顺序取用（蓝/橙/青/黄/品红/绿），不按排名、不循环。
青、黄、品红三色在浅色底上对比度低于 3:1，因此所有柱状图都带直接数值标签，
告警表也照常显示数值——颜色从不单独承载信息。
风险等级用状态色（绿/黄/橙/红），并且总是同时写出文字等级。
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import httpx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from settings import is_local_endpoint  # noqa: E402

# 分类色固定顺序（已用调色板校验脚本验证相邻色对 CVD 可分辨）
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"]
RISK_COLORS = {
    "info": "#898781",
    "low": "#0ca30c",
    "medium": "#fab219",
    "high": "#ec835a",
    "critical": "#d03b3b",
}
RISK_TEXT = {"info": "提示", "low": "低", "medium": "中", "high": "高", "critical": "严重"}
INK_MUTED = "#898781"
GRID = "#e1e0d9"


st.set_page_config(page_title="NetSentinel-LLM 看板", layout="wide")


# ------------------------------------------------------------------ 取数


def api(path: str, **params):
    url = CENTER.rstrip("/") + path
    try:
        resp = httpx.get(url, params=params, headers={"X-Probe-Token": TOKEN}, timeout=10,
                         trust_env=not is_local_endpoint(CENTER))
    except httpx.HTTPError as exc:
        return None, f"连不上中心服务 {url}：{exc}"
    if resp.status_code != 200:
        detail = resp.json().get("detail", resp.text) if resp.content else resp.text
        return None, f"中心端返回 {resp.status_code}：{detail}"
    return resp.json(), None


def api_post(path: str, body: dict):
    url = CENTER.rstrip("/") + path
    try:
        resp = httpx.post(url, json=body, headers={"X-Probe-Token": TOKEN}, timeout=60,
                          trust_env=not is_local_endpoint(CENTER))
    except httpx.HTTPError as exc:
        return None, f"连不上中心服务 {url}：{exc}"
    if resp.status_code != 200:
        detail = resp.json().get("detail", resp.text) if resp.content else resp.text
        return None, f"中心端返回 {resp.status_code}：{detail}"
    return resp.json(), None


# ------------------------------------------------------------------ 侧栏

with st.sidebar:
    st.header("连接")
    CENTER = st.text_input("中心服务地址", value=os.environ.get("NETSENTINEL_CENTER", "http://127.0.0.1:8000"))
    TOKEN = st.text_input(
        "探针 Token", type="password", value=os.environ.get("NETSENTINEL_TOKEN", "")
    )
    window = st.selectbox("统计时间范围", ["最近 10 分钟", "最近 1 小时", "最近 6 小时", "最近 24 小时"], index=1)
    minutes = {"最近 10 分钟": 10, "最近 1 小时": 60, "最近 6 小时": 360, "最近 24 小时": 1440}[window]
    live = st.toggle("自动刷新（2 秒）", value=True)
    st.caption("抓包需要 root；探针 token 与 config.yaml 的 center.token 一致。")
    st.divider()
    assistant_open = st.session_state.get("assistant_open", False)
    if st.button("收起聊天助手" if assistant_open else "打开聊天助手", key="assistant_toggle"):
        st.session_state["assistant_open"] = not assistant_open

if not TOKEN:
    st.warning("请先在侧栏填 Token（或设置环境变量 NETSENTINEL_TOKEN）")
    st.stop()


# ------------------------------------------------------------------ 聊天助手


@st.fragment
def render_assistant() -> None:
    """看板助手：自由对话，数字由中心端从库里现拍一份快照带进提示词。

    放在 fragment 里，问答只重跑这一块，不把标签页冲回第一个。
    """
    panel = st.container(height=340, border=True)
    with panel:
        history = st.session_state.setdefault("assistant_history", [])
        if not history:
            st.caption("可以问：现在看板上有多少告警？PortScan 和 DDoS 怎么区分？"
                       "收到 Heartbleed 告警先做什么？")
        for msg in history:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

    question = st.chat_input("和助手聊两句", key="assistant_input")
    if not question:
        return
    history.append({"role": "user", "content": question})
    with panel:
        with st.chat_message("user"):
            st.markdown(question)
        with st.chat_message("assistant"):
            with st.spinner("思考中…"):
                res, err = api_post(
                    "/api/v1/assistant",
                    {"question": question, "history": history[:-1]},
                )
            if err:
                # 发失败的那句不留在历史里，否则下一轮会把它当成真的说过
                history.pop()
                st.error(err)
            else:
                # 就地渲染，不调 st.rerun：整页运行时 scope="fragment" 是非法参数
                st.markdown(res["answer"])
                history.append({"role": "assistant", "content": res["answer"]})


if st.session_state.get("assistant_open"):
    render_assistant()


def money_fmt(n: int) -> str:
    return f"{n:,}"


# ------------------------------------------------------------------ 顶部指标

tab_live, tab_alerts, tab_report, tab_history = st.tabs(["实时总览", "告警", "诊断报告", "历史查询"])


def render_tiles(stats: dict) -> None:
    total = stats.get("total_flows", 0)
    alerts = stats.get("alerts", [])
    attack = total - stats.get("by_prediction", {}).get("BENIGN", 0)
    llm = stats.get("llm", {})
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("流总数", money_fmt(total))
    c2.metric("告警数", money_fmt(len(alerts)))
    c3.metric("非 BENIGN 流", money_fmt(attack), delta=f"{attack / total:.1%}" if total else None)
    c4.metric("大模型", "可用" if llm.get("available") else "未配置 key",
              delta=f"失败 {llm.get('failures', 0)} 次" if llm.get("failures") else None,
              delta_color="inverse" if llm.get("failures") else "off")


def base_layout(fig: go.Figure, title: str, height: int = 300) -> go.Figure:
    fig.update_layout(
        title=dict(text=title, font=dict(size=14)),
        height=height,
        margin=dict(l=8, r=8, t=40, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
        font=dict(size=12),
    )
    fig.update_xaxes(gridcolor=GRID, zeroline=False, linecolor="#c3c2b7")
    fig.update_yaxes(gridcolor=GRID, zeroline=False, linecolor="#c3c2b7")
    return fig


# ------------------------------------------------------------------ 实时总览


def draw_live() -> None:
    stats, err = api("/api/v1/stats", since=time.time() - minutes * 60)
    if err:
        st.error(err)
        return
    render_tiles(stats)

    left, right = st.columns([3, 2])

    with left:
        timeline = stats.get("timeline") or []
        if timeline:
            df = pd.DataFrame(timeline)
            df["time"] = pd.to_datetime(df["bucket"] * 10, unit="s")
            fig = go.Figure(
                go.Scatter(
                    x=df["time"], y=df["n"], mode="lines",
                    line=dict(color=SERIES[0], width=2),
                    hovertemplate="%{x|%H:%M:%S}<br>%{y} 条流<extra></extra>",
                )
            )
            base_layout(fig, "每 10 秒的流数量")
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
        else:
            st.info("窗口内还没有流。启动探针后：`python -m probe.sniffer --iface eth0`")

    with right:
        by_pred = stats.get("by_prediction") or {}
        if by_pred:
            order = sorted(by_pred.items(), key=lambda kv: -kv[1])
            names = [k for k, _ in order]
            vals = [v for _, v in order]
            colors = [SERIES[i % len(SERIES)] for i in range(len(names))]
            fig = go.Figure(
                go.Bar(
                    x=vals, y=names, orientation="h",
                    marker=dict(color=colors, line=dict(color="#fcfcfb", width=2)),
                    text=[money_fmt(v) for v in vals], textposition="outside",
                    hovertemplate="%{y}：%{x} 条<extra></extra>",
                )
            )
            base_layout(fig, "小模型判定分布（直接标数值）", height=300)
            fig.update_xaxes(showgrid=True)
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})
        else:
            st.info("暂无判定结果")

    by_proto = stats.get("by_protocol") or {}
    if by_proto:
        label = {"6": "TCP", "17": "UDP", "1": "ICMP"}
        names = [label.get(k, f"协议 {k}") for k in by_proto]
        vals = list(by_proto.values())
        fig = go.Figure(
            go.Bar(
                x=names, y=vals,
                marker=dict(color=[SERIES[i % len(SERIES)] for i in range(len(names))],
                            line=dict(color="#fcfcfb", width=2)),
                text=[money_fmt(v) for v in vals], textposition="outside",
                hovertemplate="%{x}：%{y} 条<extra></extra>",
            )
        )
        base_layout(fig, "协议构成", height=260)
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    draw_flow_table()


PROTO_NAME = {"6": "TCP", "17": "UDP", "1": "ICMP"}


def draw_flow_table() -> None:
    """会话流水表。中心只回展示用的几个特征列，78 维整包不下发（200 行会过 1 MB）。"""
    data, err = api("/api/v1/flows", limit=200, since=time.time() - minutes * 60)
    if err:
        st.error(err)
        return
    flows = data.get("flows") or []
    if not flows:
        st.info("窗口内还没有会话。")
        return

    rows = []
    for f in flows:
        proto, src_ip, src_port, dst_ip, dst_port = (f["flow_key"].split("|") + [""] * 5)[:5]
        dur = f["summary"].get("Flow Duration")
        rows.append(
            {
                "时间": pd.to_datetime(f["last_seen"], unit="s").strftime("%H:%M:%S"),
                "探针": f["probe_id"],
                "协议": PROTO_NAME.get(proto, proto),
                "源": f"{src_ip}:{src_port}",
                "目的": f"{dst_ip}:{dst_port}",
                "时长(s)": round(dur / 1e6, 3) if isinstance(dur, (int, float)) else None,
                "前向包": f["summary"].get("Total Fwd Packets"),
                "后向包": f["summary"].get("Total Backward Packets"),
                "判定": f["predicted"],
                "置信度": f"{f['confidence']:.3f}",
            }
        )
    st.dataframe(pd.DataFrame(rows), width="stretch", height=320, hide_index=True)


with tab_live:
    if live:
        st.fragment(run_every=2.0)(draw_live)()
    else:
        st.button("刷新", key="refresh_live")
        draw_live()


# ------------------------------------------------------------------ 告警


def draw_alerts() -> None:
    data, err = api("/api/v1/alerts", limit=200)
    if err:
        st.error(err)
        return
    alerts = data.get("alerts", [])
    if not alerts:
        st.info("窗口内没有告警。")
        return

    df = pd.DataFrame(alerts)
    df["风险"] = df["risk"].map(lambda r: RISK_TEXT.get(r, r))
    df["时间"] = pd.to_datetime(df["created_at"], unit="s").dt.strftime("%m-%d %H:%M:%S")
    # source='rule' 的行，confidence 那列是"超出阈值多少倍"，不是概率，不能按百分比展示
    src = df["source"].fillna("model") if "source" in df.columns else pd.Series(
        "model", index=df.index)
    df["来源"] = src.map(lambda s: "规则" if s == "rule" else "小模型")
    df["判定值"] = [
        f"{float(c):.2f}×" if s == "rule" else f"{float(c):.1%}"
        for c, s in zip(df["confidence"], src)
    ]
    show = df[["id", "时间", "probe_id", "category", "来源", "判定值", "风险", "flow_key"]].rename(
        columns={"id": "编号", "probe_id": "探针", "category": "类别",
                 "flow_key": "流标识"}
    )

    c1, c2 = st.columns([2, 3])
    with c1:
        cats = ["全部"] + sorted(df["category"].unique())
        pick = st.selectbox("按类别过滤", cats)
        view = show if pick == "全部" else show[df["category"] == pick]
        st.dataframe(view, width="stretch", hide_index=True, height=420)
        ids = view["编号"].tolist()
        if ids:
            current = st.session_state.get("alert_id")
            index = ids.index(current) if current in ids else 0
            chosen = st.selectbox("查看哪条告警的流标识", ids, index=index, key="alert_pick")
            # 不在这里 st.rerun(scope="app")：那一刻会连实时页一起重跑，
            # 整页重跑会把标签页冲回第一个。报告页自己每 10 秒刷一次，够跟上了。
            st.session_state["alert_id"] = int(chosen)
    with c2:
        by_cat = df["category"].value_counts()
        fig = go.Figure(
            go.Bar(
                x=by_cat.values, y=by_cat.index, orientation="h",
                marker=dict(color=[SERIES[i % len(SERIES)] for i in range(len(by_cat))],
                            line=dict(color="#fcfcfb", width=2)),
                text=by_cat.values, textposition="outside",
                hovertemplate="%{y}：%{x} 条告警<extra></extra>",
            )
        )
        base_layout(fig, "告警类别分布", height=260)
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

        risk_counts = df["risk"].value_counts()
        parts = "　".join(
            f"{RISK_TEXT.get(k, k)} {v}" for k, v in risk_counts.items()
        )
        st.caption(f"风险分布：{parts}")
        st.caption("提示：行为与端口扫描一致的资产盘点和健康检查是最常见的误报来源，"
                   "处置前先核对源 IP 的归属。")


with tab_alerts:
    if live:
        st.fragment(run_every=5.0)(draw_alerts)()
    else:
        st.button("刷新", key="refresh_alerts")
        draw_alerts()


# ------------------------------------------------------------------ 诊断报告


def draw_report() -> None:
    alert_id = st.session_state.get("alert_id")
    if not alert_id:
        st.info("先在「告警」标签里选一条告警。")
        return

    data, err = api(f"/api/v1/alerts/{alert_id}")
    if err:
        st.error(err)
        return

    alert = data["alert"]
    report = data.get("report")
    head = st.columns([3, 1, 1])
    with head[0]:
        st.subheader(f"#{alert_id} {alert['category']}")
    with head[1]:
        if alert.get("source") == "rule":
            st.caption(f"规则命中（超出阈值 {float(alert['confidence']):.2f} 倍）")
        else:
            st.caption(f"置信度 {float(alert['confidence']):.1%}")
    with head[2]:
        st.markdown(
            f"<span style='color:{RISK_COLORS.get(alert['risk'], INK_MUTED)}'>"
            f"● {RISK_TEXT.get(alert['risk'], alert['risk'])}</span>",
            unsafe_allow_html=True,
        )
    st.caption(f"探针 {alert['probe_id']}　流标识 `{alert['flow_key']}`")

    if report:
        st.markdown(report["content"])
        st.caption(f"报告 #{report['id']}　模型 {report['model']}　耗时 {report['elapsed_ms']} ms")
    else:
        st.info("这份告警还没有报告。")
    col_a, col_b = st.columns([1, 1])
    if col_a.button("重新生成报告", key="regen"):
        res, err = api_post("/api/v1/diagnose", {"alert_id": alert_id, "force": True})
        if err:
            st.error(err)
        else:
            st.success("已提交，几秒后自动刷新")
    with col_b:
        st.caption("大模型不可用时，报告会退化为模板版并明确标注。")


with tab_report:
    if live:
        st.fragment(run_every=10.0)(draw_report)()
    else:
        draw_report()


# ------------------------------------------------------------------ 历史查询


with tab_history:
    st.subheader("历史告警")
    c1, c2, c3 = st.columns(3)
    with c1:
        probe_filter = st.text_input("探针编号（留空不过滤）", value="")
    with c2:
        since_day = st.date_input("起始日期", value=pd.Timestamp.today().normalize())
    with c3:
        cat_filter = st.text_input("类别（留空不过滤）", value="")
    params = {"limit": 500, "since": float(pd.Timestamp(since_day).timestamp())}
    if probe_filter:
        params["probe_id"] = probe_filter
    if cat_filter:
        params["category"] = cat_filter
    data, err = api("/api/v1/alerts", **params)
    if err:
        st.error(err)
    else:
        rows = data.get("alerts", [])
        if rows:
            df = pd.DataFrame(rows)
            df["时间"] = pd.to_datetime(df["created_at"], unit="s").dt.strftime("%Y-%m-%d %H:%M:%S")
            df["风险"] = df["risk"].map(lambda r: RISK_TEXT.get(r, r))
            src = df["source"].fillna("model") if "source" in df.columns else pd.Series(
                "model", index=df.index)
            df["来源"] = src.map(lambda s: "规则" if s == "rule" else "小模型")
            st.dataframe(
                df[["id", "时间", "probe_id", "category", "来源", "confidence", "风险", "flow_key"]]
                .rename(columns={"id": "编号", "probe_id": "探针", "category": "类别",
                                 "confidence": "置信度/超阈值倍数", "flow_key": "流标识"}),
                width="stretch", hide_index=True,
            )
            st.download_button(
                "下载 CSV",
                df.to_csv(index=False).encode("utf-8"),
                file_name=f"alerts_{since_day}.csv",
                mime="text/csv",
            )
        else:
            st.info("该条件下没有告警记录。")
