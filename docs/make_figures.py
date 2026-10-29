#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NetSentinel-LLM 报告插图生成脚本。

用法：python3 docs/make_figures.py
产出：docs/figures/*.png（300 dpi）

★ 尺寸约定：报告版心宽 15.2 cm（约 6.3 in）。图按 figsize 宽 8.4 in 出，
  放进 Word 时缩到 0.75 倍，图内 8.6 pt 字号实际印出来约 6.4 pt。
  调大 figsize 会让字号跟着缩水，改布局后请按"有效字号 = 字号 × 6.3 / figsize宽"复核。
"""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # 必须在 import pyplot 之前，见 matplotlib-qtagg-cv2-crash

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "Noto Sans CJK JP", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

OUT = Path(__file__).resolve().parent / "figures"
OUT.mkdir(parents=True, exist_ok=True)

FIG_W, FIG_H = 8.4, 5.25          # 英寸，比例固定 1.6，对应数据坐标 160 × 100
FS_BODY = 8.6                     # 框内正文
FS_HEAD = 10.0                    # 框内标题
FS_GROUP = 10.0                   # 分组标题
FS_NOTE = 8.6                     # 箭头标注
PT_PER_UNIT = FIG_W * 72 / 160.0  # 每个数据坐标单位对应的点数

INK = "#1d2b3a"
GREY = "#4f5f70"

C = {
    "edge": ("#2f6f9f", "#e8f1f8"),
    "center": ("#2f7d5c", "#e7f2ec"),
    "llm": ("#7a4d92", "#f1eaf6"),
    "view": ("#b87333", "#fbf0e3"),
    "plain": ("#4a5a6a", "#f3f5f7"),
    "net": ("#5b6b7c", "#eef0f2"),
}


# ---------------------------------------------------------------- 绘图原语
def canvas(w=160, h=100):
    fig = plt.figure(figsize=(FIG_W, FIG_H), dpi=300)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, w)
    ax.set_ylim(0, h)
    ax.set_aspect("auto")
    ax.axis("off")
    return fig, ax


def group(ax, x, y, w, h, title, key):
    ec, fc = C[key]
    ax.add_patch(
        FancyBboxPatch(
            (x, y), w, h,
            boxstyle="round,pad=0,rounding_size=1.0",
            linewidth=1.1, edgecolor=ec, facecolor=fc,
            linestyle=(0, (6, 3)), zorder=1,
        )
    )
    ax.text(x + 1.5, y + h - 2.4, title, ha="left", va="center",
            fontsize=FS_GROUP, color=ec, weight="bold", zorder=3)


def box(ax, x, y, w, h, head, body="", key="plain", fs=FS_BODY, hs=FS_HEAD,
        dashed=False, lw=1.4, head_top=False):
    ec, fc = C[key]
    ax.add_patch(
        FancyBboxPatch(
            (x, y), w, h,
            boxstyle="round,pad=0,rounding_size=1.0",
            linewidth=lw, edgecolor=ec, facecolor=fc, zorder=2,
            linestyle=(0, (4, 3)) if dashed else "-",
        )
    )
    xm = x + w / 2
    if not body:
        ty = (y + h - 3.4) if head_top else (y + h / 2)
        ax.text(xm, ty, head, ha="center", va="center",
                fontsize=hs * 0.95, color=INK, zorder=3, linespacing=1.5)
        return
    # head 顶部对齐（并排的框标题才在同一水平线上），body 在剩余区域居中
    head_h = hs * 1.35 / PT_PER_UNIT
    body_h = (body.count("\n") + 1) * fs * 1.5 / PT_PER_UNIT
    head_cy = y + h - 1.5 - head_h / 2
    area_top = head_cy - head_h / 2 - 1.5
    body_cy = (y + 0.5 + area_top) / 2
    ax.text(xm, head_cy, head, ha="center", va="center",
            fontsize=hs, color=ec, weight="bold", zorder=3, linespacing=1.35)
    ax.text(xm, body_cy, body, ha="center", va="center",
            fontsize=fs, color=INK, zorder=3, linespacing=1.5)


def arrow(ax, p, q, label="", color=GREY, style="-|>", lw=1.5, dashed=False,
          lab_xy=None, ha="center", va="center"):
    ax.add_patch(
        FancyArrowPatch(
            p, q, arrowstyle=style, mutation_scale=13, linewidth=lw,
            color=color, zorder=2, shrinkA=0, shrinkB=0,
            linestyle=(0, (4, 3)) if dashed else "-",
        )
    )
    if label:
        lx, ly = lab_xy if lab_xy else ((p[0] + q[0]) / 2, (p[1] + q[1]) / 2)
        ax.text(lx, ly, label, ha=ha, va=va, fontsize=FS_NOTE, color=color,
                zorder=5, linespacing=1.7,
                bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="none", alpha=0.96))


def elbow(ax, pts, color=GREY, lw=1.4, dashed=True):
    for a, b in zip(pts[:-2], pts[1:-1]):
        ax.plot([a[0], b[0]], [a[1], b[1]], color=color, lw=lw, zorder=2,
                linestyle=(0, (4, 3)) if dashed else "-")
    ax.add_patch(
        FancyArrowPatch(
            pts[-2], pts[-1], arrowstyle="-|>", mutation_scale=13, linewidth=lw,
            color=color, zorder=2, shrinkA=0, shrinkB=0,
            linestyle=(0, (4, 3)) if dashed else "-",
        )
    )


# ---------------------------------------------------------------- 图 1 系统架构
def fig_architecture():
    fig, ax = canvas()

    box(ax, 8, 3, 144, 9, "实验网段：正常业务流量 + 攻击流量（M7 脚本 · nmap 对照）",
        key="net", hs=9.5)

    group(ax, 8, 21, 144, 23, "边缘层  两台 PC 探针（scapy + 网卡混杂模式）", "edge")
    box(ax, 16, 23, 62, 16, "探针 A（PC-1，兼开发主机）",
        "M1 实时抓包 · 多协议首部解析\nM2 会话聚合与统计特征（对齐 CIC 口径）", "edge")
    box(ax, 82, 23, 62, 16, "探针 B（PC-2，兼攻击机）",
        "M1 抓包与解析（与 A 同构部署）\nM7 端口扫描 / SYN Flood / Ping Flood", "edge")

    group(ax, 8, 52, 78, 29, "中心层  云服务器 · FastAPI", "center")
    box(ax, 11, 65, 33, 12, "M6 上报接收与鉴权", "FastAPI 路由 · Token 校验", "center")
    box(ax, 49, 65, 33, 12, "SQLite 存储", "会话特征 / 告警 / 报告", "center")
    box(ax, 11, 52.5, 33, 11, "M3 小模型推理", "M8 对比 · M11 规则基线", "center")
    box(ax, 49, 52.5, 33, 11, "M9 RAG 检索", "字符二元组 BM25 · 知识 Top-3", "center")

    group(ax, 108, 52, 44, 29, "大模型层  商用 API", "llm")
    box(ax, 111, 54, 38, 22, "M4 DeepSeek / 通义千问",
        "HTTPS · OpenAI 兼容 SDK\n专家角色提示词\n固定输出 schema\n多轮追问", "llm")

    box(ax, 8, 88, 144, 11, "M5 Streamlit 实时看板 · M10 双探针对比",
        "报文流水表 │ 协议占比与时序图 │ 攻击告警表 │ 诊断报告面板 │ 历史查询", "view")

    arrow(ax, (40, 12), (40, 21))
    arrow(ax, (120, 12), (120, 21))
    ax.text(80, 16.2, "原始以太网帧", ha="center", va="center", fontsize=FS_NOTE,
            color=GREY, zorder=5, bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="none"))

    arrow(ax, (32, 43), (32, 52), lw=1.7)
    ax.text(30, 47.5, "① 会话特征 + 报文摘要\nHTTP/JSON · Token 鉴权",
            ha="right", va="center", fontsize=FS_NOTE, color=GREY, zorder=5, linespacing=1.7,
            bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="none", alpha=0.96))
    arrow(ax, (72, 52), (72, 43))
    ax.text(74, 47.5, "告警回执 /\n阈值配置下发",
            ha="left", va="center", fontsize=FS_NOTE, color=GREY, zorder=5, linespacing=1.7,
            bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="none", alpha=0.96))

    arrow(ax, (86, 72), (108, 72), lw=1.7)
    ax.text(97, 76.5, "② 诊断请求\n（证据+知识）", ha="center", va="center",
            fontsize=FS_NOTE, color=GREY, zorder=5, linespacing=1.7,
            bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="none", alpha=0.96))
    arrow(ax, (108, 61), (86, 61))
    ax.text(97, 57, "③ 诊断报告\n（JSON）", ha="center", va="center",
            fontsize=FS_NOTE, color=GREY, zorder=5, linespacing=1.7,
            bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="none", alpha=0.96))

    arrow(ax, (60, 81), (60, 88), lw=1.7)
    ax.text(58, 84.5, "④ 告警与诊断报告实时推送（HTTP/WebSocket）",
            ha="right", va="center", fontsize=FS_NOTE, color=GREY, zorder=5, linespacing=1.7,
            bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="none", alpha=0.96))

    fig.savefig(OUT / "fig1_architecture.png", dpi=300)
    plt.close(fig)


# ---------------------------------------------------------------- 图 2 小模型结构
def fig_ml_model():
    fig, ax = canvas()

    ax.text(4.5, 94, "（a）离线训练：一次性产出模型文件（models/train.py）",
            ha="left", va="center", fontsize=10.2, color=INK, weight="bold")

    xs, w, gap, yb, hb = 4.5, 27.0, 4.0, 63, 24
    train = [
        ("CIC-IDS2017 抽样",
         "CSV 版 6 类\nBenign / PortScan\nDDoS / DoS Hulk\nFTP / SSH-Patator"),
        ("数据清洗", "缺失值 / ∞ 值\n去重 · 异常剔除"),
        ("分层划分 + 预处理", "训练:验证:测试\n= 7 : 2 : 1\nStandardScaler\nclass_weight"),
        ("五模型训练", "决策树 / 随机森林\nXGBoost / 逻辑回归\n混合森林（新增）"),
        ("评估与模型产物", "P / R / F1 · 混淆矩阵\n特征重要性排序\nbest_model.pkl"),
    ]
    for i, (head, body) in enumerate(train):
        x = xs + i * (w + gap)
        box(ax, x, yb, w, hb, head, body, "center")
        if i:
            arrow(ax, (x - gap, yb + hb / 2), (x, yb + hb / 2))

    ax.text(4.5, 41.5, "（b）在线推理：每 2 s 一个聚合窗口",
            ha="left", va="center", fontsize=10.2, color=INK, weight="bold")

    xs2, w2, gap2, yb2, hb2 = 3.5, 23.0, 3.2, 8, 24
    infer = [
        ("特征向量（M2）", "五元组会话聚合\n对齐 CIC 口径"),
        ("预处理", "复用训练期\nscaler 参数"),
        ("分类器推理", "best_model\npredict_proba\n类别概率输出"),
        ("类别 + 置信度", "BENIGN / PortScan\nDDoS / DoS Hulk\nFTP / SSH-Patator"),
        ("证据打包", "Top-k 特征取值\n报文摘要"),
        ("M4 LLM 诊断", "转图 3\n大模型诊断"),
    ]
    for i, (head, body) in enumerate(infer):
        x = xs2 + i * (w2 + gap2)
        key = "llm" if i == len(infer) - 1 else "plain"
        box(ax, x, yb2, w2, hb2, head, body, key)
        if i:
            arrow(ax, (x - gap2, yb2 + hb2 / 2), (x, yb2 + hb2 / 2))

    x_model = xs + 4 * (w + gap) + w / 2
    x_clf = xs2 + 2 * (w2 + gap2) + w2 / 2
    elbow(ax, [(x_model, yb), (x_model, 47.5), (x_clf, 47.5), (x_clf, yb2 + hb2)])
    ax.text((x_model + x_clf) / 2 + 10, 48.1, "加载模型文件",
            ha="center", va="bottom", fontsize=FS_NOTE, color=GREY, zorder=5,
            bbox=dict(boxstyle="round,pad=0.26", fc="white", ec="none", alpha=0.96))

    fig.savefig(OUT / "fig2_ml_model.png", dpi=300)
    plt.close(fig)


# ---------------------------------------------------------------- 图 2b 混合森林内部结构
def fig_hybrid_forest():
    fig, ax = canvas()

    box(ax, 40, 88, 80, 10, "训练集：分层抽样后（约 30 万 × 78 维）", key="center", hs=9.5)

    ax.text(3, 84.5, "Bagging\nbootstrap 采样\n+ 随机特征子集",
            ha="left", va="center", fontsize=FS_NOTE, color=GREY, zorder=5, linespacing=1.6)

    # 分叉总线
    ax.plot([80, 80], [88, 84.5], color=GREY, lw=1.4, zorder=2)
    ax.plot([28, 132], [84.5, 84.5], color=GREY, lw=1.4, zorder=2)
    for x in (28, 80, 132):
        arrow(ax, (x, 84.5), (x, 76))

    box(ax, 6, 52, 44, 24, "基学习器 #1",
        "随机抽到 XGBoost\n内部浅树 depth ≤ 6\n提升 100 轮", "center")
    box(ax, 58, 52, 44, 24, "基学习器 #2",
        "随机抽到 LightGBM\n内部浅树 depth ≤ 6\n提升 100 轮", "llm")
    box(ax, 110, 52, 44, 24, "基学习器 #N",
        "随机抽到 CatBoost\n内部浅树 depth ≤ 6\n提升 100 轮", "edge")

    # 汇聚总线
    for x in (28, 80, 132):
        ax.plot([x, x], [52, 47], color=GREY, lw=1.4, zorder=2)
    ax.plot([28, 132], [47, 47], color=GREY, lw=1.4, zorder=2)
    arrow(ax, (80, 47), (80, 44))

    box(ax, 36, 30, 88, 14, "软投票聚合（Soft Voting）",
        "p = (p1 + p2 + … + pN) / N，逐类平均后取最大", "plain")
    arrow(ax, (80, 30), (80, 24))
    box(ax, 44, 10, 72, 14, "输出：6 类概率 + 置信度", key="view", hs=9.5)

    ax.text(80, 3.5,
            "与随机森林的唯一区别：基学习器由单棵 CART 换成一个小型提升模型，Bagging 骨架与随机特征子集不变",
            ha="center", va="center", fontsize=8.0, color=GREY)

    fig.savefig(OUT / "fig2b_hybrid_forest.png", dpi=300)
    plt.close(fig)


# ---------------------------------------------------------------- 图 3 LLM 诊断管线
def fig_llm_pipeline():
    fig, ax = canvas()

    yb, hb = 54, 24
    box(ax, 2, yb, 33, hb, "输入：小模型输出",
        "类别 + 置信度\nTop-k 特征取值\n代表性报文摘要", "plain")
    box(ax, 43, yb, 33, hb, "M9 RAG 检索",
        "查询构造（类别+特征）\nBM25 检索 Top-3\n知识片段（可溯源）", "center")
    box(ax, 84, yb, 33, hb, "提示词组装",
        "系统角色：运维专家\n知识片段 + 证据\n输出 schema 约束", "plain")
    box(ax, 125, yb, 33, hb, "LLM 推理",
        "DeepSeek API\ntemperature = 0.2\n超时 / 重试 / 降级", "llm")

    for x in (35, 76, 117):
        arrow(ax, (x, yb + hb / 2), (x + 8, yb + hb / 2))

    box(ax, 43, 84, 33, 14, "离线：教材 + RFC 摘要",
        "12 条中文知识\n→ 字符二元组索引", "center", dashed=True, lw=1.2)
    arrow(ax, (59.5, 84), (59.5, yb + hb), dashed=True)

    box(ax, 110, 84, 48, 14, "看板内多轮追问",
        "携带上一轮报告 + 新问题\n重新进入提示词组装", "view", dashed=True, lw=1.2)
    arrow(ax, (134, 84), (134, yb + hb), dashed=True)

    box(ax, 2, 4, 156, 40,
        "结构化诊断报告（llm/schema.py · Pydantic 强校验，字段缺失即拒绝落库）",
        "", "llm", hs=10.0, head_top=True)
    arrow(ax, (141.5, yb), (141.5, 44), lw=1.7)

    fields = [
        ("事件概述", "summary"),
        ("风险等级", "risk"),
        ("证据链", "evidence"),
        ("处置建议", "actions"),
        ("协议原理回顾", "principle"),
    ]
    fw, fg, x0 = 27.5, 3.2, 5.0
    for i, (zh, en) in enumerate(fields):
        fx = x0 + i * (fw + fg)
        ax.add_patch(
            FancyBboxPatch(
                (fx, 9), fw, 23,
                boxstyle="round,pad=0,rounding_size=1.0",
                linewidth=1.2, edgecolor=C["view"][0], facecolor="white", zorder=3,
            )
        )
        ax.text(fx + fw / 2, 25.5, zh, ha="center", va="center",
                fontsize=9.6, color=C["view"][0], weight="bold", zorder=4)
        ax.text(fx + fw / 2, 16.8, en, ha="center", va="center",
                fontsize=8.4, color=GREY, zorder=4)

    fig.savefig(OUT / "fig3_llm_pipeline.png", dpi=300)
    plt.close(fig)


if __name__ == "__main__":
    fig_architecture()
    fig_ml_model()
    fig_hybrid_forest()
    fig_llm_pipeline()
    for p in sorted(OUT.glob("*.png")):
        print(f"{p.name}  {p.stat().st_size // 1024} KB")
