# -*- coding: utf-8 -*-
"""生成《计算机网络技术课程答辩报告》docx。

    python3 docs/build_report.py

产物：docs/NetSentinel-LLM课程答辩报告.docx

结构按要求组织：封面 / 一、课题综述 / 二、任务内容（含分工）/ 三、任务实现（按人分章，
每人一章，章内含本人负责模块的**完整源代码**）/ 四、参考文献。

代码直接从工作区读取，不手抄；数字来自 models/artifacts/ 下的产物文件与本次运行截图。
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

from docx import Document
from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "NetSentinel-LLM课程答辩报告.docx"
ASSETS = ROOT / "docs" / "report_assets"
FIGS = ROOT / "docs" / "figures"

BODY_CM = 15.2
HEI = "黑体"
SONG = "宋体"
MONO = "Consolas"
TNR = "Times New Roman"
CENTER = WD_ALIGN_PARAGRAPH.CENTER

doc = Document()
_code_no = 0


# ----------------------------------------------------------------- 基础排版


def style_font(style_name: str, east: str, size: float, bold: bool, latin: str | None = None):
    st = doc.styles[style_name]
    rPr = st.element.get_or_add_rPr()
    rFonts = rPr.find(qn("w:rFonts"))
    if rFonts is None:
        rFonts = OxmlElement("w:rFonts")
        rPr.insert(0, rFonts)
    for attr, val in (("w:ascii", latin or east), ("w:hAnsi", latin or east),
                      ("w:eastAsia", east)):
        rFonts.set(qn(attr), val)
    st.font.size = Pt(size)
    st.font.bold = bold
    st.font.color.rgb = RGBColor(0, 0, 0)


def run_font(run, east: str, size: float, bold: bool = False, latin: str | None = None):
    run.font.size = Pt(size)
    run.font.bold = bold
    run.font.color.rgb = RGBColor(0, 0, 0)
    rPr = run._element.get_or_add_rPr()
    rFonts = rPr.find(qn("w:rFonts"))
    if rFonts is None:
        rFonts = OxmlElement("w:rFonts")
        rPr.insert(0, rFonts)
    for attr, val in (("w:ascii", latin or east), ("w:hAnsi", latin or east),
                      ("w:eastAsia", east)):
        rFonts.set(qn(attr), val)


def body(text: str, indent: bool = True, after: float = 0, size: float = 12):
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.line_spacing = 1.5
    pf.space_before = Pt(0)
    pf.space_after = Pt(after)
    pf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    if indent:
        pf.first_line_indent = Pt(size * 2)
    run_font(p.add_run(text), SONG, size, latin=TNR)
    return p


def bullet(text: str, size: float = 12):
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.line_spacing = 1.5
    pf.space_before = Pt(0)
    pf.space_after = Pt(0)
    pf.left_indent = Pt(size * 2)
    pf.first_line_indent = Pt(-size)
    pf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    run_font(p.add_run(text), SONG, size, latin=TNR)
    return p


def h1(text: str, new_page: bool = True):
    p = doc.add_heading(level=1)
    p.paragraph_format.page_break_before = new_page
    p.paragraph_format.space_before = Pt(18)
    p.paragraph_format.space_after = Pt(10)
    p.paragraph_format.line_spacing = 1.5
    run_font(p.add_run(text), HEI, 16, bold=True)
    return p


def h2(text: str, new_page: bool = False):
    p = doc.add_heading(level=2)
    p.paragraph_format.page_break_before = new_page
    p.paragraph_format.space_before = Pt(12)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.5
    run_font(p.add_run(text), HEI, 14, bold=True)
    return p


def h3(text: str):
    p = doc.add_heading(level=3)
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.line_spacing = 1.5
    run_font(p.add_run(text), HEI, 12, bold=True)
    return p


def table_caption(text: str):
    p = doc.add_paragraph()
    p.alignment = CENTER
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.keep_with_next = True
    run_font(p.add_run(text), HEI, 10.5, bold=True)


def png_size(path: Path) -> tuple[int, int]:
    with open(path, "rb") as fh:
        head = fh.read(26)
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"不是 PNG：{path}")
    return struct.unpack(">II", head[16:24])


def figure(path: Path, caption: str, max_h_cm: float = 18.5):
    w_px, h_px = png_size(path)
    w_cm = BODY_CM
    h_cm = w_cm * h_px / w_px
    if h_cm > max_h_cm:
        h_cm = max_h_cm
        w_cm = h_cm * w_px / h_px
    p = doc.add_paragraph()
    p.alignment = CENTER
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.keep_with_next = True
    p.add_run().add_picture(str(path), width=Cm(w_cm))
    cap = doc.add_paragraph()
    cap.alignment = CENTER
    cap.paragraph_format.space_before = Pt(0)
    cap.paragraph_format.space_after = Pt(10)
    run_font(cap.add_run(caption), SONG, 10.5)


def _shade(cell, fill: str):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tcPr.append(shd)


def table(headers, rows, widths, caption=None, font_pt=9.0, left_cols=(), bold_rows=()):
    if caption:
        table_caption(caption)
    t = doc.add_table(rows=len(rows) + 1, cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.autofit = False
    for idx, w in enumerate(widths):
        t.columns[idx].width = Cm(w)

    for r_i, row in enumerate([headers] + list(rows)):
        trPr = t.rows[r_i]._tr.get_or_add_trPr()
        trPr.append(OxmlElement("w:cantSplit"))
        if r_i == 0:
            trPr.append(OxmlElement("w:tblHeader"))
        for c_i, val in enumerate(row):
            cell = t.cell(r_i, c_i)
            cell.width = Cm(widths[c_i])
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            p = cell.paragraphs[0]
            p.alignment = (WD_ALIGN_PARAGRAPH.LEFT
                           if (c_i in left_cols and r_i > 0) else CENTER)
            p.paragraph_format.space_before = Pt(1.5)
            p.paragraph_format.space_after = Pt(1.5)
            p.paragraph_format.line_spacing = 1.15
            run_font(p.add_run(str(val)), SONG, font_pt,
                     bold=(r_i == 0 or r_i in bold_rows), latin=TNR)
            if r_i == 0:
                _shade(cell, "EDEDED")

    gap = doc.add_paragraph()
    gap.paragraph_format.space_before = Pt(0)
    gap.paragraph_format.space_after = Pt(6)
    run_font(gap.add_run(""), SONG, 6)


def hrule():
    p = doc.add_paragraph()
    pPr = p._p.get_or_add_pPr()
    pBdr = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    for k, v in (("w:val", "single"), ("w:sz", "8"), ("w:space", "1"),
                 ("w:color", "000000")):
        bottom.set(qn(k), v)
    pBdr.append(bottom)
    pPr.insert(0, pBdr)


def add_field(paragraph, instr: str, size: float = 10.5):
    run = paragraph.add_run()
    run_font(run, SONG, size, latin=TNR)
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    text = OxmlElement("w:instrText")
    text.set(qn("xml:space"), "preserve")
    text.text = f" {instr} "
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.append(begin)
    run._r.append(text)
    run._r.append(end)


def code_file(rel: str, note: str = "", size: float = 8.0):
    """把工作区里的一个源文件完整排进报告，按行断段（避免一行被拆到两页）。"""
    global _code_no
    path = ROOT / rel
    lines = path.read_text(encoding="utf-8").replace("\t", "    ").splitlines()
    _code_no += 1
    cap = doc.add_paragraph()
    cap.alignment = WD_ALIGN_PARAGRAPH.LEFT
    cap.paragraph_format.space_before = Pt(8)
    cap.paragraph_format.space_after = Pt(2)
    cap.paragraph_format.keep_with_next = True
    run_font(cap.add_run(f"代码 3-{_code_no}　{rel}"), HEI, 9, bold=True)
    run_font(cap.add_run(f"（{len(lines)} 行）" + (f"　{note}" if note else "")), SONG, 9)
    for line in lines:
        p = doc.add_paragraph()
        pf = p.paragraph_format
        pf.line_spacing = 1.0
        pf.space_before = Pt(0)
        pf.space_after = Pt(0)
        pf.left_indent = Pt(0)
        pf.widow_control = False
        run_font(p.add_run(line), SONG, size, latin=MONO)
    end = doc.add_paragraph()
    end.paragraph_format.space_before = Pt(0)
    end.paragraph_format.space_after = Pt(8)
    run_font(end.add_run(""), SONG, 6)


def code_text(text: str, caption: str, size: float = 8.0):
    """把一段非常驻文本（如 JSON 知识库）排版成代码块。"""
    global _code_no
    _code_no += 1
    cap = doc.add_paragraph()
    cap.alignment = WD_ALIGN_PARAGRAPH.LEFT
    cap.paragraph_format.space_before = Pt(8)
    cap.paragraph_format.space_after = Pt(2)
    cap.paragraph_format.keep_with_next = True
    run_font(cap.add_run(f"代码 3-{_code_no}　{caption}"), HEI, 9, bold=True)
    for line in text.splitlines():
        p = doc.add_paragraph()
        pf = p.paragraph_format
        pf.line_spacing = 1.0
        pf.space_before = Pt(0)
        pf.space_after = Pt(0)
        pf.widow_control = False
        run_font(p.add_run(line), SONG, size, latin=MONO)
    end = doc.add_paragraph()
    end.paragraph_format.space_before = Pt(0)
    end.paragraph_format.space_after = Pt(8)
    run_font(end.add_run(""), SONG, 6)


# ----------------------------------------------------------------- 页面与样式

style_font("Normal", SONG, 12, False, latin=TNR)
doc.styles["Normal"].paragraph_format.line_spacing = 1.5
style_font("Heading 1", HEI, 16, True)
style_font("Heading 2", HEI, 14, True)
style_font("Heading 3", HEI, 12, True)

section = doc.sections[0]
section.page_width = Cm(21)
section.page_height = Cm(29.7)
section.top_margin = Cm(2.54)
section.bottom_margin = Cm(2.54)
section.left_margin = Cm(2.9)
section.right_margin = Cm(2.9)
section.different_first_page_header_footer = True

footer_p = section.footer.paragraphs[0]
footer_p.alignment = CENTER
run_font(footer_p.add_run("第 "), SONG, 10.5)
add_field(footer_p, "PAGE")
run_font(footer_p.add_run(" 页"), SONG, 10.5)


# ----------------------------------------------------------------- 封面

doc.add_paragraph()

p = doc.add_paragraph()
p.alignment = CENTER
p.paragraph_format.space_after = Pt(6)
run_font(p.add_run("天津理工大学华信软件学院"), HEI, 26, bold=True)

p = doc.add_paragraph()
p.alignment = CENTER
p.paragraph_format.space_after = Pt(18)
run_font(p.add_run("2024 级计算机网络技术课程答辩报告"), HEI, 22, bold=True)

hrule()

doc.add_paragraph()

p = doc.add_paragraph()
p.alignment = CENTER
p.paragraph_format.space_after = Pt(2)
run_font(p.add_run("题目："), HEI, 16, bold=True)

p = doc.add_paragraph()
p.alignment = CENTER
p.paragraph_format.space_after = Pt(2)
p.paragraph_format.line_spacing = 1.3
run_font(p.add_run("基于 Scapy 与机器学习的智能网络流量嗅探分析"), HEI, 16, bold=True)

p = doc.add_paragraph()
p.alignment = CENTER
p.paragraph_format.space_after = Pt(2)
p.paragraph_format.line_spacing = 1.3
run_font(p.add_run("及大语言模型诊断系统"), HEI, 16, bold=True)

p = doc.add_paragraph()
p.alignment = CENTER
p.paragraph_format.space_after = Pt(20)
run_font(p.add_run("（NetSentinel-LLM）"), SONG, 14)

doc.add_paragraph()

for label, value in (("组　　长", "姚霖锋"),
                     ("组　　员", "孙贤泽　　潘凤乐　　王储"),
                     ("班　　级", "＿＿＿＿＿＿＿＿"),
                     ("指导教师", "＿＿＿＿＿＿＿＿")):
    p = doc.add_paragraph()
    p.alignment = CENTER
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.line_spacing = 1.5
    run_font(p.add_run(f"{label}：{value}"), SONG, 14)

p = doc.add_paragraph()
p.alignment = CENTER
p.paragraph_format.space_before = Pt(28)
run_font(p.add_run("2026 年 10 月"), SONG, 14)

doc.add_page_break()


# ----------------------------------------------------------------- 一、课题综述

h1("一、课题综述", new_page=False)

h2("1.1 问题的提出")
body("网络嗅探是计算机网络课程里最直观的一类实验：把网卡置为混杂模式，抓取经过的每一个以太网帧，"
     "再逐层解封装到 IP 首部与 TCP/UDP 首部，就能看见网络里到底在传什么。tcpdump 与 Wireshark "
     "把这件工作做到了极致，但它们有一个共同前提——判断由人来做。一段几万个包的抓包文件，"
     "初学者靠肉眼找出端口扫描或洪水攻击，实际上做不到；即便找到了，也说不清这条流为什么异常、"
     "依据是哪个字段、下一步该封哪个方向。")
body("另一方面，课程里讲到的防火墙与入侵检测系统（Snort、Suricata）解决的是“自动报警”，"
     "但报警的输出形态是一行规则名加一个五元组。它回答“命中了哪条规则”，不回答“这条流是什么、"
     "为什么可疑、该怎么处置”。规则还要人工维护，而现实中的协议种类与攻击变体远多于任何一份规则集。"
     "本课题想验证的问题是：能不能在“看见”（嗅探）之外，把“判断”和“解释”两步也自动化，"
     "拼成一条从原始以太网帧到中文处置建议的完整链路。")

h2("1.2 现有方案的不足")
body("第一类是陈列式。Wireshark 的强项是把协议字段结构化地摊开给人看，它的价值在“可核查”，"
     "不在“可判断”。本项目的做法不是取代它，而是把它的输出当作下游的证据来源——"
     "我们同时保留 pcap 与会话特征 CSV，任何一条告警都能回到 Wireshark 里逐帧核对。")
body("第二类是规则式。规则判据是确定性的、可解释的，但覆盖面受规则集限制。更关键的是，"
     "同一条规则在不同采集口径下的数值含义可能完全不同：数据集里“单包流”的包长统计只有 0、2、6 三种取值，"
     "因为那是 L4 载荷字节；我们改前按 IP 总长统计，一个 40 字节的纯 SYN 就被记成 40。"
     "规则写得越精细，这种口径错配造成的静默误差越大。")
body("第三类是封闭式。商用流量分析产品给出一个风险分数，用户拿不到分数是怎么来的，也无法追问"
     "“如果是内网主机被攻陷发起的，处置顺序有什么不同”。大语言模型的出现让这一步第一次有可能被自动化："
     "把结构化证据交给它，用固定 schema 约束它的输出，它就能按协议机制写出一份可读的中文报告。")

h2("1.3 本课题的技术路线")
body("我们把任务拆成四步，对应智能体的“感知—思考—行动—反馈”闭环：感知是把原始以太网帧解析成"
     "双向会话并按 CICFlowMeter 口径汇总成 78 维特征向量；思考是机器学习模型给出类别与置信度；"
     "行动是规则引擎兜底、大语言模型生成诊断报告；反馈是看板实时展示、支持追问、可导出。")
body("系统按这四个动作分成四层：边缘层（两台 PC 探针，抓包与特征）、中心层（云服务器上的 FastAPI 服务，"
     "鉴权、存储、推理、告警）、大模型层（DeepSeek 主用、通义千问备用）、展示层（Streamlit 看板）。")
body("这里有一个主动做出的设计判断需要说明：我们**没有**把整件事交给一个大模型。原因有三条。"
     "其一是速度与成本：2 秒一个窗口的实时判断如果每次都调用大模型，单条流的判定延迟从毫秒级变成秒级，"
     "调用次数还与流量成正比。其二是可复现：分类器加载的是持久化的模型文件，同一输入必得同一输出；"
     "大模型带温度采样，同一输入两次结果不完全一致，不能当分类器用。其三是幻觉：让大模型直接“看包”"
     "判断攻击，它会把“典型 SYN Flood 的表现”当成“本次流量的表现”来写，报告读起来很专业但内容是编的。"
     "所以分工是——小模型负责判断并给出证据，大模型只在这个结论之上做解释与处置建议，"
     "并且被提示词明确禁止改判、禁止引用未给定的证据。")
body("另一条判断是：协议类型不交给机器学习。TCP/UDP/ICMP 由 IP 首部的 protocol 字段直接确定，"
     "是确定性事实，用规则解析即可；机器学习只用在“载荷加密、规则难以穷尽”的统计行为层面，"
     "例如端口扫描、洪水攻击、暴力破解。这条写在 3.3 节。")

h2("1.4 完成情况一览")
body("项目共划分 11 个模块，当前完成 10 个，1 个未完成（M10 双探针联动演示）。"
     "代码 5 677 行（不含文档与本报告生成脚本），单元测试 59 条全部通过。按验收口径逐项对照见下表。")
table(
    ["模块", "名称", "状态", "负责人", "说明"],
    [
        ["M1", "数据包嗅探与协议解析", "完成", "姚霖锋", "scapy 抓包、双向会话表、pcap 落盘"],
        ["M2", "流量特征工程", "完成", "孙贤泽", "78 维 CICFlowMeter 口径特征，与数据集口径对齐"],
        ["M3", "小模型攻击检测", "完成", "孙贤泽", "训练 5 个候选，在线只加载 1 个 best_model.pkl"],
        ["M4", "大模型自然语言诊断", "完成", "潘凤乐", "五段式结构化报告 + 多轮追问 + 模板降级"],
        ["M5", "Web 可视化看板", "完成", "王储", "实时总览 / 告警 / 诊断报告 / 历史查询"],
        ["M6", "中心服务与边缘通信", "完成", "姚霖锋", "FastAPI 八个路由，Token 鉴权，SQLite 四表"],
        ["M7", "攻击复现实验台", "完成", "姚霖锋", "端口扫描 / SYN 洪泛 / ping 洪泛，带安全护栏"],
        ["M8", "模型对比实验", "完成", "孙贤泽", "五模型同口径对比，前向滚动验证选型"],
        ["M9", "RAG 协议知识库", "完成", "潘凤乐", "12 条协议知识，字符二元组 BM25 检索"],
        ["M10", "双探针联动演示", "未完成", "姚霖锋", "设计完成，第二台机器未到位，未做端到端演示"],
        ["M11", "阈值规则引擎基线", "完成", "王储", "单流规则 + 窗口规则 + 去重域，同口径评测"],
    ],
    widths=[1.4, 4.6, 1.6, 1.8, 5.8],
    caption="表 1-1　模块完成情况",
    left_cols=(1, 4),
)
body("需要说明的两点限制，后面的实现章节会展开：其一是本机没有 CAP_NET_RAW 权限，"
     "抓包模块无法在答辩机上对真实网卡运行，演示时用一个回放脚本把数据集中的会话经真实 HTTP 接口送进中心，"
     "被替换的只有“帧从哪里来”这一环；其二是项目只在一台机器上完整跑通过，"
     "M10 的双探针协同只是设计，没有联调。")


# ----------------------------------------------------------------- 二、任务内容

h1("二、任务内容")

h2("2.1 总体任务")
body("总目标是构建一个可演示、可评测、边界清楚的四层网络流量分析系统，把“抓包—判定—解释—展示”"
     "串成一条闭环链路，并对每一环给出可复现的量化证据。具体分解为五项任务：")
bullet("（1）写一个基于 scapy 的探针，能把一段流量解析成双向会话，并按 CICFlowMeter 口径汇总成 78 维特征；")
bullet("（2）实现中心服务，接收探针上报、鉴权落库、调用分类器、产生告警；")
bullet("（3）训练并对比五个分类模型，用站得住的口径选出上线模型；")
bullet("（4）接入大语言模型，把告警的证据链转成结构化的中文诊断报告，并支持追问；")
bullet("（5）做一个看板，实时展示流量、告警与报告，让人能在浏览器里用起来。")

h2("2.2 模块划分")
body("11 个模块的划分依据是“每一块能单独验收”。模块之间只通过三个接口耦合：探针 → 中心的 HTTP 上报、"
     "中心 → 大模型的 JSON 请求、中心 → 看板的只读查询。这样任何一块出问题都能被定位到具体模块，"
     "也便于四个人并行开发。模块与源文件的对应关系如下。")
table(
    ["模块", "名称", "对应源文件", "关键产出"],
    [
        ["M1", "数据包嗅探与协议解析", "probe/sniffer.py", "双向会话表、pcap 与特征 CSV"],
        ["M2", "流量特征工程", "probe/features.py", "78 维特征向量、feature_schema.json"],
        ["M3", "小模型攻击检测", "center/inference.py", "Detector：批推理 + Top-k 证据打包"],
        ["M4", "大模型自然语言诊断", "llm/prompts.py、llm/client.py、llm/schema.py", "五段式报告、多轮追问、模板降级"],
        ["M5", "Web 可视化看板", "dashboard/app.py", "四个标签页与自动刷新"],
        ["M6", "中心服务与边缘通信", "center/main.py、center/database.py、probe/reporter.py", "八个路由、四张表、上报客户端"],
        ["M7", "攻击复现实验台", "attack/*.py", "三支攻击脚本与安全护栏"],
        ["M8", "模型对比实验", "models/train.py、models/hybrid_forest.py", "comparison.json、best_model.pkl"],
        ["M9", "RAG 协议知识库", "llm/rag.py、data/rag/chunks.json", "12 条知识、BM25 检索"],
        ["M10", "双探针联动演示", "（贯穿 M1—M6）", "设计文档，未联调"],
        ["M11", "阈值规则引擎基线", "center/rules.py、tools/rules_baseline.py", "规则引擎、rules_baseline.json"],
    ],
    widths=[1.4, 4.2, 5.6, 4.0],
    caption="表 2-1　模块与源文件的对应关系",
    font_pt=8.5,
    left_cols=(1, 2, 3),
)

h2("2.3 小组分工")
body("四名成员按“链路位置”分工，而不是按“写文档 / 写代码”分工：每人负责的模块都在同一条数据通路上，"
     "改动自己的模块时能直接看到下游反应。需要说明的是，仓库 README 里早期按两人（同学 A / 同学 B）"
     "预留的模块归属是立项时的草案，四人组队后按下表细化落实。")
table(
    ["姓名", "角色", "承担模块", "主要工作内容"],
    [
        ["姚霖锋", "组长", "M1、M6、M7、M10",
         "负责总体方案、模块划分与进度把控；基于 scapy 实现抓包与协议解析、双向会话表与 pcap 落盘；"
         "实现 FastAPI 中心服务、Token 鉴权、SQLite 存储与告警分级；编写三支攻击复现脚本并加安全护栏；"
         "负责整体集成联调（中心 + 看板 + 大模型 + 回放脚本）与答辩材料汇总。"],
        ["孙贤泽", "组员", "M2、M3、M8",
         "实现 78 维 CICFlowMeter 口径特征提取，负责在线提取器与数据集的三处口径对齐（包长、标志位、"
         "聚合形态）并补回归测试；封装模型训练与在线推理；设计并执行五模型同口径对比实验，"
         "确定“随机划分 → 类内按时间 → 前向滚动验证”的选型口径演进与最终选型。"],
        ["潘凤乐", "组员", "M4、M9",
         "设计诊断提示词（含三条铁律：不许改判、只许引用给定证据、必须回到协议层）与五段式输出 schema；"
         "构建 12 条协议知识并用字符二元组 BM25 实现检索；实现多轮追问链路；"
         "实现大模型不可用时的模板降级路径；负责数据集抽样脚本，并核对每份报告的字段完整性。"],
        ["王储", "组员", "M5、M11",
         "实现 Streamlit 看板的四个标签页、图表与自动刷新机制，处理规则告警“超阈值倍数”与小模型置信度的"
         "展示差异；实现阈值规则引擎（单流规则 + 窗口规则 + 按域去重）与规则基线评测脚本；"
         "负责 59 条单元测试。"],
    ],
    widths=[1.8, 1.3, 2.8, 9.3],
    caption="表 2-2　小组分工",
    font_pt=8.5,
    left_cols=(2, 3),
)
body("为保证分工在文档里可追溯，第三章按人分四节，每节先讲本人负责模块的设计与实测结果，"
     "再把本人编写的源文件**完整**列出（不是节选）。任何一个数字、任何一段代码，"
     "都能对应到具体的人与具体的文件。")

h2("2.4 进度安排")
table(
    ["周次", "时间", "主要工作", "交付物"],
    [
        ["第 1 周", "第 1—7 天",
         "选题论证、方案设计、数据集下载与抽样、开发环境搭建", "任务书草案、数据样本与清单"],
        ["第 2 周", "第 8—14 天",
         "打通最小链路：抓包 → 特征 → 上报 → 中心落库 → 判定", "可运行的探针与中心服务"],
        ["第 3 周", "第 15—21 天",
         "接入大模型与知识库、实现看板、实现规则引擎", "可演示的四层系统、规则基线数字"],
        ["第 4 周", "第 22—28 天",
         "五模型对比与选型、端到端联调、单元测试、报告撰写", "本报告、截图证据、答辩材料"],
    ],
    widths=[2.0, 2.4, 7.0, 3.8],
    caption="表 2-3　进度安排",
    left_cols=(2, 3),
)

h2("2.5 验收指标", new_page=True)
body("下面的指标在立项时确定，实测值全部来自仓库内的产物文件与本次运行的截图，没有手填。"
     "其中“相对规则基线的提升”这一项是后来补充的——做完规则引擎之后我们才意识到，"
     "只说“准确率 0.97”没有意义，必须有一个同口径的确定性下限作对照。")
table(
    ["指标", "目标", "实测值"],
    [
        ["单条会话的特征维度", "78（对齐 CICFlowMeter）", "78"],
        ["检测类别数", "6 类", "BENIGN / DDoS / DoS Hulk / PortScan / Patator / Heartbleed"],
        ["小模型留出集 macro-F1", "≥ 0.95", "0.9719（xgboost，最后 10% 封存集）"],
        ["相对阈值规则基线的提升", "可量化", "+0.3924（0.9719 对 0.5795，同一段测试集）"],
        ["单份诊断报告生成耗时", "< 10 s", "4.6—9.9 s，中位 4.97 s"],
        ["报告正文字数", "≥ 800 字", "中位 1 122 字"],
        ["单元测试", "全部通过", "59 条全部通过"],
    ],
    widths=[5.4, 4.2, 5.6],
    caption="表 2-4　验收指标与实测值",
    left_cols=(0, 2),
)
body("每一项都能在本机复现，复现命令与对应产物如下：模型指标来自 "
     "python models/train.py --split temporal-cv（产物 models/artifacts/comparison.json）；"
     "规则基线来自 python tools/rules_baseline.py（产物 rules_baseline.json）；"
     "报告耗时与字数来自 reports 表的 elapsed_ms 与 content 长度；单元测试来自 python -m pytest。"
     "复现时唯一需要外部条件的是大模型耗时——它受网络与模型服务负载影响，"
     "所以我们报的是区间与中位数，而不是单次最优值。")


# ----------------------------------------------------------------- 三、任务实现

h1("三、任务实现")

h2("3.1 系统总体架构与工程骨架")
body("四层之间只有三条纵向连接：边缘层向中心层做 HTTPS/JSON 上报并接收告警回执；中心层向大模型层发一次"
     "诊断请求并收回结构化报告；中心层向展示层提供只读查询接口。原始以太网帧只在实验网段与边缘层之间流动，"
     "不出局域网。")
figure(FIGS / "fig1_architecture.png", "图 3-1　系统总体架构（云边协同；①—④ 为单次检测的数据流）")
body("这张图里有一处需要强调：中心层的推理、规则、检索都在同一个进程里串行调用，没有引入消息队列。"
     "对两周周期的课设而言，多一个中间件就多一个失效点；代价是连续大流量下上报接口会被推理阻塞，"
     "这一点作为已知限制写在 3.8.2 节。")
body("工程骨架包含四样东西：一份统一的 config.yaml（默认值，本地覆盖写 config.local.yaml 深度合并）、"
     "一个 settings.py（配置加载与“这个地址算不算本机/局域网”的判定）、一份 requirements.txt，"
     "以及 pytest.ini。其中 settings.is_local_endpoint 是被反复用到的一个小函数——"
     "探针连局域网中心、看板连中心时都要据此决定 trust_env，否则本机写坏的代理变量会把请求带偏。")
table(
    ["类别", "组件", "说明"],
    [
        ["运行环境", "Ubuntu（Linux 6.8）、Python 3.10", "开发与演示在同一台笔记本上完成"],
        ["抓包解析", "Scapy", "纯 Python 构造与解析以太网帧、IP、TCP/UDP"],
        ["机器学习", "scikit-learn、XGBoost、LightGBM、CatBoost", "五模型对比与在线推理"],
        ["服务端", "FastAPI + Uvicorn、SQLite", "八个 HTTP 路由，四张表"],
        ["大模型", "DeepSeek Chat API（备用：通义千问）", "HTTP 调用，temperature 0.2"],
        ["前端", "Streamlit + Plotly", "四标签页看板，fragment 局部刷新"],
        ["测试", "pytest", "59 条，以合成数据为主"],
        ["代码量", "5 677 行 Python + 643 行文档", "probe/center/llm/models/tools/attack/dashboard/tests"],
    ],
    widths=[2.6, 6.6, 6.0],
    caption="表 3-1　开发环境与工具链",
    left_cols=(1, 2),
)
body("下面把公共骨架与本报告配图脚本一并列出，供复现环境使用。它们不属于任何一个人的专有模块，"
     "但少了这些文件整个工程起不来。")
code_file("settings.py", "配置加载与局域网判定")
code_file("config.yaml", "统一配置（仅存密钥的环境变量名，不含明文 key）")
code_file("requirements.txt")
code_file("pytest.ini", "关掉与本机 io 插件冲突的 anyio 插件")
code_file("docs/make_figures.py", "四张设计图的生成脚本")


# ====================================================== 3.2 姚霖锋
h2("3.2 姚霖锋：嗅探、中心服务与攻击复现（M1 / M6 / M7 / M10）")
body("本人负责的是“数据从哪里来、落后到哪里去”这一段：边缘侧的抓包与上报、中心侧的接口与存储、"
     "以及与检测链路配套的攻击复现脚本。这一段是整条链路的骨架，下游的特征、模型、大模型、看板都挂在它上面。")
table(
    ["文件", "行数", "职责"],
    [
        ["probe/sniffer.py", "245", "网卡抓包、双向会话聚合、pcap 与特征 CSV 落盘"],
        ["probe/reporter.py", "83", "批次上报客户端，带列序名与 Token"],
        ["center/main.py", "278", "八个 HTTP 路由，上报 → 推理 → 告警 → 后台诊断"],
        ["center/database.py", "293", "SQLite 四张表、查询与补列迁移"],
        ["attack/*.py", "212", "端口扫描、SYN 洪泛、ping 洪泛与共用的安全护栏"],
    ],
    widths=[4.2, 2.0, 9.0],
    caption="表 3-2　本部分涉及的源文件",
    left_cols=(0, 2),
)

h3("3.2.1 抓包与会话聚合")
body("探针用 scapy 在指定网卡上抓包，逐层解封装到 IP 与传输层首部，取出五元组、时间戳、标志位、"
     "载荷长度等原始量，再按“双向会话”聚合：以 (协议, IP_A, port_A, IP_B, port_B) 的规范化形式作键，"
     "A/B 两端按固定顺序归一，保证同一会话的正反两个方向落进同一条记录。会话在空闲超过阈值后封口，"
     "输出一条完整记录。")
body("有几个细节是踩过坑之后才定下来的。空闲超时取 120 秒，与 CIC-IDS2017 的采集口径一致；"
     "默认的 30 秒会把同一条长流切成好几段，特征向量的形态随之全变。原始帧同时按 pcap 格式落盘，"
     "会话特征另存 CSV，两者用会话键关联，任何一条告警都能回到 Wireshark 里逐帧核对——"
     "这也是“陈列式”工具在本项目里的位置：不取代它，而是把它当作可核查的下游证据源。")
body("探针不负责判断，只负责“把帧变成一行数字”。这条边界是刻意划的：如果把分类器放到探针里，"
     "每台机器都要带一份模型与 scaler，模型一更新就要重新分发；放到中心则只需要更新一处。"
     "代价是上报带宽，所以上报的是特征向量而不是原始帧。")
body("抓包需要 root 或 CAP_NET_RAW 能力。答辩机上没有这个权限，因此实际演示时用一个回放脚本"
     "替代嗅探这一环：它从数据集里按类别取会话，按每 2 秒 2 条的节奏经 POST /api/v1/report "
     "送进中心，特征向量、推理、告警、报告全部走真实代码路径，唯一被替换的是“帧从哪里来”。"
     "这一点在答辩时要主动说明，不能把回放说成真实抓包。")

h3("3.2.2 上报格式与列序校验")
body("上报报文故意带上 feature_names，让中心端能当场比对训练时的列序。这个设计看起来是多余的，"
     "但它挡住的是一类最难发现的错误：列序一旦错位，模型不会报错——它只会把“目的端口”当成“流时长”去推理，"
     "然后给出一个看起来正常的错误答案。中心端收到列序不符直接返回 400，而不是按名字重排，"
     "因为重排会把“缺列”悄悄变成“错位”。宁可丢一批数据，也不能用错位的特征去推理。")

h3("3.2.3 中心服务：鉴权、存储与告警升级")
body("中心服务是一个 FastAPI 应用。探针上报时用 X-Probe-Token 请求头做共享令牌鉴权，"
     "令牌值从 config.yaml 读入并由 hmac.compare_digest 比较，避免普通字符串比较的时序侧信道。"
     "报文结构由 Pydantic 约束，单批流数上限 2 000 条，超出返回 413。")
table(
    ["方法", "路径", "用途", "鉴权"],
    [
        ["GET", "/healthz", "健康检查与时间戳", "无"],
        ["POST", "/api/v1/report", "探针上报一批会话特征，返回被接受的条数与告警编号", "需要 Token"],
        ["GET", "/api/v1/flows", "会话流水（只回展示用特征列，78 维整包不下发）", "需要 Token"],
        ["GET", "/api/v1/alerts", "按时间、探针、类别查询告警", "需要 Token"],
        ["GET", "/api/v1/alerts/{id}", "单条告警及其诊断报告", "需要 Token"],
        ["POST", "/api/v1/diagnose", "对指定告警触发或重跑诊断", "需要 Token"],
        ["POST", "/api/v1/chat", "针对某份报告的多轮追问", "需要 Token"],
        ["GET", "/api/v1/stats", "看板用的统计（时序、分布、汇总、规则计数）", "需要 Token"],
    ],
    widths=[1.8, 4.6, 7.2, 2.4],
    caption="表 3-3　中心服务接口",
    left_cols=(1, 2),
)
body("存储用 SQLite 四张表：flows（会话特征与判定）、alerts（告警，含 source 与超阈值倍数）、"
     "reports（大模型报告正文与耗时）、chat（追问记录）。选 SQLite 是因为演示规模下单机读写足够，"
     "不需要额外部署数据库服务。表结构里留了补列逻辑——CREATE TABLE IF NOT EXISTS 不会给已存在的表加列，"
     "少了这一步，老库上读 source 列会直接 KeyError。")
body("告警与流是分开存的：每条流都留档（含原始特征），只有非 BENIGN 的升级成告警。"
     "误报分析、召回率复盘都要靠 flows 表，丢掉就没法复盘。这一点在 3.7 节里救过一次——"
     "演示时有一分钟产生了 21 条 PortScan 误报，正是靠流表里的原始特征才定位到"
     "“数据集 BENIGN 行里约 48% 是单包短流”。")
body("告警产生后，服务把诊断任务丢进 FastAPI 的 BackgroundTasks，接口立即返回，不阻塞上报方；"
     "看板轮询时再取报告。这样大模型慢或挂掉，检测链路照常工作，只是报告变成模板版并在界面上标注。")

h3("3.2.4 攻击复现与安全护栏")
body("攻击复现用于验证检测链路与做对照实验，共三支：端口扫描、SYN 洪泛、ping 洪泛，"
     "都用 scapy 自行构造报文，nmap 仅作对照组的参照。三支脚本共用一层安全护栏（attack/common.py）："
     "目标地址必须落在本人授权的实验网段白名单内，发包速率与总次数各有上限，超出即中止。"
     "**这些脚本仅限在本人授权的实验网段内使用，不得对任何第三方目标运行。**")
body("需要如实说明的是，由于答辩机没有抓包权限，攻击复现与检测链路的联动没有在真实网卡上跑通过；"
     "端口扫描与 SYN 洪泛的效果验证依赖的是数据集回放与规则引擎的窗口判据实测（3.5 节）。"
     "这项验证在拿到带 CAP_NET_RAW 的机器后应当补做。")

h3("3.2.5 M10 双探针联动：设计完成、未联调")
body("M10 的设计是：两台探针使用同一中心、同一令牌，靠 probe_id 区分；中心按 probe_id 聚合，"
     "看板提供按探针过滤的能力；演示场景是一台探针看正常业务、另一台发起攻击，"
     "用两台机器的视角对比“同一段攻击在两个位置看到的样子”。数据层面的准备已经完成"
     "（探针编号贯穿上报、存储、告警、查询全链路，看板与历史查询都支持按探针过滤），"
     "端到端演示没有做——第二台机器未到位，且两边都没有抓包权限。这一项记为未完成，列入后续工作。")

h3("3.2.6 本部分完整代码")
body("以下五个文件为本部分全部代码，按“探针 → 上报 → 中心服务 → 存储 → 攻击复现”的顺序排列。"
     "代码中原有的注释一并保留，因为其中相当一部分记录的是“为什么这样写”而不是“这段在做什么”。")
code_file("probe/sniffer.py", "M1 抓包与会话聚合")
code_file("probe/reporter.py", "M6 边缘侧上报通道")
code_file("center/main.py", "M6 中心服务")
code_file("center/database.py", "M6 SQLite 存储")
code_file("attack/common.py", "M7 安全护栏")
code_file("attack/portscan.py", "M7 端口扫描（仅限授权网段）")
code_file("attack/synflood.py", "M7 SYN 洪泛（仅限授权网段）")
code_file("attack/pingflood.py", "M7 ping 洪泛（仅限授权网段）")

h3("3.2.7 小结")
body("本部分交付了系统的骨架：探针能把帧变成带列序名的特征批次，中心能鉴权、落库、推理并把非 BENIGN 流"
     "升级成告警，攻击复现脚本能在授权网段内构造对照流量。骨架的价值在于“下游可以独立开发”："
     "特征、模型、大模型、看板四块都在它之上并行完成，最终由本人在 3.6 节做端到端联调。"
     "未完成的部分是 M10 的双探针联调，原因写在 3.2.5 节，不掩饰。")


# ====================================================== 3.3 孙贤泽
h2("3.3 孙贤泽：特征工程、小模型与五模型对比（M2 / M3 / M8）")
body("本人负责“把一行特征变成一个有依据的类别”这一段：特征的构造与口径对齐、分类器的训练与在线封装、"
     "以及五个模型的同口径对比实验。这一段决定了系统的判断能力，也决定了报告里能写出什么样的数字。")
table(
    ["文件", "行数", "职责"],
    [
        ["probe/features.py", "452", "78 维 CICFlowMeter 口径特征提取"],
        ["center/inference.py", "136", "Detector：模型加载、批推理、Top-k 证据打包"],
        ["models/train.py", "591", "数据清洗、三档划分、五模型训练与选型"],
        ["models/labels.py", "31", "标签归一化（含被写坏的 en dash）"],
        ["models/hybrid_forest.py", "306", "第五个模型：Bagging 骨架 + 随机提升器"],
    ],
    widths=[4.2, 2.0, 9.0],
    caption="表 3-4　本部分涉及的源文件",
    left_cols=(0, 2),
)

h3("3.3.1 78 维特征的组织")
body("78 维特征按 CICFlowMeter 的口径组织，分八组：基本量（流时长、前向/后向包数与字节数）、"
     "速率类（Flow Bytes/s、Flow Packets/s）、包长统计（均值、标准差、最大最小）、TCP 标志位计数、"
     "首部长度、活跃/空闲时间、子流统计、批量（bulk）统计。特征列名与顺序由 feature_schema.json 固定，"
     "训练与推理共用同一份 scaler 参数，保证两侧是同一把尺子。")
body("这一节最重要的工作不是写 78 个公式，而是把在线提取器的口径对齐到数据集。逐列核对时发现三处"
     "“列名一样、算法不一样”的地方，它们都不会报错，只会让线上向量悄悄落到训练分布之外。")
body("还有一处分工是刻意的：协议类型不交给机器学习。TCP/UDP/ICMP 由 IP 首部的 protocol 字段直接确定，"
     "是确定性事实，用规则解析即可；机器学习只用在“载荷加密、规则难以穷尽”的统计行为层面，"
     "例如端口扫描、洪水攻击、暴力破解。78 维特征里也没有任何一维是“协议号”，因为一旦把它当特征，"
     "模型就可能学出“看到 UDP 就报 DDoS”这类与流量行为无关的捷径。")
table(
    ["特征列", "数据集口径", "我们改前的口径", "判据"],
    [
        ["Packet Length 系列、Total Length of Fwd/Bwd Packets、Average Packet Size、Flow Bytes/s",
         "L4 载荷字节（不含 IP/TCP 首部）", "IP 总长度",
         "数据集里单包流的这些列只取 0、2、6 三种值；改前一个 40 字节的纯 SYN 被记成 40"],
        ["八个 * Flag Count 与 Fwd/Bwd PSH/URG Flags",
         "0/1，表示该标志是否出现过", "出现次数",
         "全表 RST/ECE/CWE 恒为 0，PSH Flag Count 只有 {0,1}；改前 200 包洪流给出 Fwd PSH Flags=200，"
         "相对全表 z≈1006"],
        ["流的聚合形态", "长流慢速（中位 84.9 s、6 个前向包）", "短流突发（0.1 s、200 个前向包）",
         "不是 bug，是采集方式的差异；见下文"],
    ],
    widths=[4.6, 3.6, 3.4, 3.6],
    caption="表 3-5　在线提取器与数据集的三处口径错配",
    font_pt=8.5,
    left_cols=(0, 1, 2, 3),
)
body("前两处已经按数据集口径改掉，并各留一条回归测试钉住："
     "test_packet_length_columns_count_l4_payload_only 与 test_flag_columns_are_indicators_not_counts。"
     "第三处不是错误而是数据集的采集方式：CIC-IDS2017 里的“DoS Hulk”是一条跨 85 秒、6 个前向包的慢流，"
     "而我们现场构造的同名流量是 0.1 秒 200 个包的突发。按数据集形态手工造一条流（6 个前向小包 + "
     "6 个后向 1656 字节包、跨 85 s、PSH 置位），其余各列都能对上，判定仍是 BENIGN 0.9999。")

h3("3.3.2 数据准备与抽样口径")
body("使用 CIC-IDS2017 官方的 8 个 MachineLearningCVE CSV（2 830 743 行 × 79 列、844 MB），"
     "按类配额抽成六类小样本：BENIGN 116 860、DDoS 40 000、PortScan 32 655、DoS Hulk 30 394、"
     "Patator 9 150、Heartbleed 11，清洗后共 229 070 行 × 78 维（丢弃 297 行含缺失值或无穷值，"
     "去掉 24 479 行完全重复行）。")
body("之所以按类配额抽而不按比例抽，是因为全量里 BENIGN 占 80.3%、Heartbleed 只有 11 行。"
     "按比例抽到 25 万行，Heartbleed 只剩 1 行，7:2:1 划分后测试集 0 行，这个类等于被抹掉。"
     "代价必须写明：训练集的类别先验被人为抬高了（BENIGN 从 80.3% 降到 47.3%），"
     "所以本样本上的准确率不能当作线上准确率——真实部署里 80% 是正常流量，误报率的含义完全不同。")
figure(FIGS / "fig2_ml_model.png",
       "图 3-2　小模型结构：（a）离线训练一次性产出模型文件；（b）在线推理复用训练期的 scaler 与特征口径")

h3("3.3.3 选型口径的三次修正")
body("第一次用分层随机划分，四个模型全部落在 0.999 附近，极差小于 0.001，名次由噪声决定。"
     "我们没有把这个数字当结论，而是去找它为什么这么高：CIC-IDS2017 的随机划分会把同一天的近似重复流"
     "同时分到训练集和测试集（抽样的 25 万行里 9.7% 是完全重复行，去重后仍剩大量只差几个字段的短流）。"
     "最直接的证据是 XGBoost 与一棵决策树只差 0.0002——如果 0.999 反映了模型对攻击行为的建模能力，"
     "多出来的 1 799 棵树不可能一点用都没有。")
body("第二次改成类内按时间划分（每类最早的 70% 训练、接下来 20% 验证、最后 10% 测试）。"
     "这一版暴露了另一个问题：用单段验证集选型等于抛硬币。random_forest 与 xgboost 在验证集上完全并列"
     "（0.9975 对 0.9975），在最后 10% 上却差 0.0243；按验证集选会选中 random_forest，而测试集说的是 xgboost。"
     "单段验证集紧贴训练段的尾部，同一段流量里的近似重复还在，它测不出“再往后滑一段会不会失手”。")
body("第三次用前向滚动验证（expanding window）：把前 90% 的开发段按类内时间再切 3 块，第 k 折用前 k 块训练、"
     "第 k+1 块验证，最后 10% 全程封存、只在最后报一次。这是本项目最终采用的口径"
     "（训练 206 163 行、封存测试 22 907 行）。另外，考虑到 Heartbleed 测试集只有 1 个样本，"
     "判对判错直接摆动六分之一的总分，选型改用剔除样本数少于 30 的类之后的 macro-F1"
     "（记作 reliable macro-F1）。")

h3("3.3.4 五模型同口径对比结果")
table(
    ["模型", "滚动验证均值（3 折）", "标准差", "最后 10% 准确率", "reliable macro-F1", "树数", "训练耗时"],
    [
        ["决策树", "0.9782", "0.0234", "0.9714", "0.9674", "1", "3.38 s"],
        ["随机森林", "0.9806", "0.0255", "0.9590", "0.9562", "100", "4.43 s"],
        ["XGBoost", "0.9817", "0.0249", "0.9715", "0.9719", "1 800", "12.69 s"],
        ["逻辑回归", "0.9419", "0.0250", "0.9739", "0.9646", "—", "18.07 s"],
        ["混合森林", "0.9770", "0.0241", "0.9452", "0.9362", "10 400", "652.30 s"],
    ],
    widths=[3.0, 4.4, 2.0, 2.6, 2.8, 1.8, 2.0],
    caption="表 3-6　五模型同口径对比（训练 206 163 行、封存测试 22 907 行）",
    font_pt=8.5,
    bold_rows=(3,),
)
figure(ASSETS / "fig_compare.png", "图 3-3　五模型对比脚本的实测输出（本机终端）")
body("这张表有两处读法要说清。第一，标准差（0.024）比模型之间的差距（0.0011）大一个量级，"
     "所以“五选一”应当如实写成并列：滚动均值只能把逻辑回归拉出来（它确实差一档），"
     "区分不出前四名。最终按均值选 XGBoost 上线，理由是它每一折都不垫底且推理最快，不是因为“它更强”。"
     "第二，退化不是“越往后越差”的单调漂移：折 1 与折 3 都在 0.99 以上，难的是折 2（0.94 附近）。"
     "难样本卡在中间，说明数据里有一段时间的流量形态与其它时段不同，而不是分布持续右移——"
     "这一点不能写成“时间越久越不准”，数据不支持那个解释。")
body("按类看召回，能发现一个被总体准确率盖住的事实：退化集中在 DoS Hulk 一类，其余五类基本持平。")
table(
    ["模型", "BENIGN", "DDoS", "DoS Hulk", "Patator", "PortScan"],
    [
        ["决策树", "0.977", "0.996", "0.899", "0.964", "0.991"],
        ["随机森林", "0.975", "0.993", "0.815", "0.974", "0.990"],
        ["XGBoost", "0.969", "0.996", "0.913", "0.997", "0.998"],
        ["逻辑回归", "0.961", "0.993", "0.972", "0.992", "0.994"],
        ["混合森林", "0.998", "0.993", "0.629", "0.945", "0.993"],
    ],
    widths=[3.2, 3.0, 3.0, 3.0, 3.0, 3.0],
    caption="表 3-7　最后 10% 封存集上的分类召回",
    bold_rows=(3,),
)
body("同样这几个模型在验证段上 DoS Hulk 召回都在 0.99 以上。含义是：一句“准确率 0.97”会把一类攻击的"
     "显著退化盖住，报告必须按类报召回。混合森林掉到 0.629 最狠，我们没有单独做消融定位成因，"
     "先如实记为观测事实，不写成解释。")

h3("3.3.5 混合森林与两条副产物结论")
body("第五个模型是本组自己设计的“混合森林”：Bagging 骨架不变（bootstrap 采样 + 随机特征子集，深度约束 24 层），"
     "但每个基学习器不再是一棵 CART，而是从 XGBoost、LightGBM、CatBoost 中随机抽一个训练出的小型提升模型"
     "（内部浅树 6 层、100 轮），最后软投票聚合。动机是让 Bagging 压方差、Boosting 压偏差两头都管。")
figure(FIGS / "fig2b_hybrid_forest.png",
       "图 3-4　混合森林内部结构（外层 Bagging，内层随机抽取的提升器，软投票聚合）")
body("实现上有三个要点。基学习器内部必须是浅树——GBDT 的表达能力来自“很多棵浅树叠加”，"
     "一棵 24 层的树几乎就能把训练集拟合完，后续提升轮次没有残差可学，等于退化成“换了个库跑单棵 CART”。"
     "三个库的概率尺度要统一，软投票前各走各自的 predict_proba。训练成本要按“树”算："
     "XGBoost/LightGBM 多分类每轮每类各长一棵树（100 轮 × 6 类 = 600 棵/基学习器），"
     "CatBoost 每轮只长一棵（叶子是 6 维向量），所以 24 个基学习器共 8×600 + 8×600 + 8×100 = 10 400 棵树。"
     "报告里报成本要报到树数，只写“100 轮”会让读者把量级估小 6 倍。")
body("结论是：混合森林没有显著超过调好的单个 XGBoost，实测反而更低。提升模型本身方差已经很低，"
     "再套一层并行平均能压的方差有限，而训练成本翻了几十倍（652.3 s / 10 400 棵 对 12.7 s / 1 800 棵，约 51 倍）；"
     "滚动均值 0.9770 低于 XGBoost 的 0.9817，最后 10% 上 0.9362 是五个模型里最低的。"
     "它的价值在设计论证而不是指标：说明我们理解 Bagging 与 Boosting 各自降低的是偏差还是方差。"
     "这一条在答辩时要主动讲，不能为了“创新点”硬说它最好。")
body("做这个模型的过程中还得到两条比模型本身更有价值的副产物结论。第一，随机特征子集在这里是负优化："
     "max_features=\"sqrt\"（每成员只看 8/78 维）时 reliable macro-F1 为 0.9899，"
     "max_features=1.0（每成员看 78 维）时是 0.9986，差 0.0087，比“三个库混不混”重要得多。"
     "原因是随机森林的 max_features 是为高方差的深树设计的，树与树去相关后平均能降方差；"
     "而提升器是低方差的浅树串行加和，随机砍掉 90% 的特征等于让每轮残差都学偏——它缺的不是方差而是信息。"
     "第二，随机划分下五个模型都落在 0.999 附近是划分泄漏，不是模型能力，理由见 3.3.3 节。")

h3("3.3.6 跨天留出实验：这是开集问题，不是泛化问题")
body("我们还做了按天留出的实验（周一到周四训练、周五测试），结果是失败的。原因是 CIC-IDS2017 的"
     "每一类攻击只出现在某一天的抓包文件里（DDoS 与 PortScan 在星期五，DoS Hulk 在星期三），"
     "所以按天划分等于把两个类别当成训练时根本没出现过的类别塞给模型。实测闭集口径下 BENIGN 告警率 0.01%，"
     "DDoS 60.05%（24 021 条全被判成 DoS Hulk），PortScan 只有 0.47% 被判为非 BENIGN；"
     "二分类口径下准确率 0.4982、攻击召回 0.3506、攻击精确率 0.9999。")
body("精确率 0.9999 配召回 0.35，说明模型只对自己见过的形状开口。这条结论要修正的是说法而不是结论本身："
     "按天划分测出来的主要是开集失败，谈泛化应当用类内按时间的前向滚动验证，谈开集就显式写成一条结论。"
     "这也正是在线路径必须保留大模型层的实测依据——小模型遇到没见过的形状时既不报警也不报错，"
     "只有把证据交给大模型才能说清“这条流是什么”[16]。")

h3("3.3.7 在线推理封装")
body("在线推理由 center/inference.py 的 Detector 负责三件事：加载 best_model.pkl 与 feature_schema.json、"
     "做批推理、把偏离训练分布最大的若干特征打包成“证据”交给下游。第三件事是这一层最容易被忽略的部分——"
     "分类器的原始输出只有一个类别名和一个概率，大模型拿到它写不出证据链，必须补上"
     "“是哪几个特征的取值远离了训练分布、偏离多少个标准差”。")
body("证据打包的判据是 z 分数：对每个特征计算 (当前值 − 训练均值) / 训练标准差，取绝对值最大的若干项。"
     "这里有一个必须交代的限制：z 分数只说明“偏离多少”，不说明“往哪个方向才是攻击”。"
     "所以证据的措辞是“PSH Flag Count = 1.0，偏离训练分布 1.228 个标准差”，"
     "而不是“PSH 异常”；是否异常由类别判定回答，z 分数只提供量化的偏离度。")

h3("3.3.8 本部分完整代码")
body("以下五个文件为本部分全部代码，按“特征 → 在线推理 → 训练与选型 → 第五个模型”的顺序排列。")
code_file("probe/features.py", "M2 78 维特征提取")
code_file("center/inference.py", "M3 在线推理与证据打包")
code_file("models/labels.py", "M8 标签归一化")
code_file("models/train.py", "M8 训练、划分与选型")
code_file("models/hybrid_forest.py", "M8 混合森林")
code_file("tools/cross_day_eval.py", "M8 跨天留出实验")

h3("3.3.9 小结")
body("本部分交付了两样东西：一是与数据集同口径的 78 维特征提取器，二是同口径、可复现的五模型对比结论。"
     "最有价值的工作不是把 XGBoost 训到 0.9719，而是识别出随机划分下的 0.999 是划分泄漏、"
     "单段验证集选型等于抛硬币，并把选型口径改成前向滚动验证。这一步之后，报告里的每个数字都带上了"
     "“它是在什么口径下量出来的”这一注解，也才有了后面与规则基线、与大模型分工的正确表述。")
body("本部分的三条结论里有两条对项目不利：混合森林没有超过单模型，跨天留出实验失败。"
     "它们都原样写进了本报告，没有包装成创新点。")


# ====================================================== 3.4 潘凤乐
h2("3.4 潘凤乐：大模型诊断、知识检索与数据构建（M4 / M9）")
body("本人负责“把一行判定变成一份人能读的报告”这一段：提示词与输出 schema、协议知识库与检索、"
     "多轮追问链路、以及大模型不可用时的降级路径。另外负责数据集抽样脚本与知识库内容。")
table(
    ["文件", "行数", "职责"],
    [
        ["llm/prompts.py", "121", "系统提示词（三条铁律）、证据与会话的格式化、请求组装"],
        ["llm/client.py", "138", "DeepSeek / 通义千问调用、重试、不可用时降级为模板报告"],
        ["llm/schema.py", "111", "输出解析与 Pydantic 校验，字段缺失即拒绝"],
        ["llm/rag.py", "81", "字符二元组 BM25 检索"],
        ["tools/build_sample.py", "223", "按类配额抽样、列名清洗、时间序号"],
        ["data/rag/chunks.json", "12 条", "协议知识库内容"],
        ["tests/test_llm_and_center.py", "170", "大模型层与中心接口的联测"],
    ],
    widths=[5.4, 2.0, 7.8],
    caption="表 3-8　本部分涉及的源文件",
    left_cols=(0, 2),
)

h3("3.4.1 为什么大模型只做解释、不做判断")
body("这一层要解决的问题是“把结构化结论翻译成可读的中文，并且不许它自由发挥”。"
     "把大模型放在分类器之上而不是替代分类器，是有代价的：多一跳网络、多一份延迟、多一个失效点。"
     "换来的是三件事：可复现（分类器同一输入同一输出）、可评测（准确率与 F1 有明确含义）、"
     "可解释（报告是给人看的，不是给指标看的）。")
figure(FIGS / "fig3_llm_pipeline.png",
       "图 3-5　大模型诊断管线（先检索知识再组提示词，输出经 schema 校验，字段缺失即拒绝落库）")

h3("3.4.2 三条铁律与五段式输出")
body("提示词里有三条铁律，写进系统提示是因为它们是这个项目最容易被模型违反的三件事：")
bullet("（1）不许改判。类别由上游分类器给出，大模型只做解释与处置建议。放任它改判，等于把一个可评测的分类器"
       "换成一个不可复现的接口。")
bullet("（2）只准引用给定证据。模型很容易把“典型 DDoS 的表现”当成“本次流量的表现”来写，报告读起来很专业，"
       "但那是编的。证据链只允许引用提示词里给出的特征值与规则命中的 detail 文本。")
bullet("（3）必须回到协议层。这是计算机网络课设，评审最关心的恰是“你懂不懂协议”，"
       "所以模板里固定有“协议原理回顾”一节，面向刚学完这门课的读者讲握手、状态机与字段语义。")
body("输出是五段式：事件概述、风险等级、证据链、处置建议、协议原理回顾，由 Pydantic 模型强校验，"
     "字段缺失或风险等级不在枚举内即拒绝落库，避免模型自由发挥。温度设为 0.2，在可读性与稳定性之间折中。"
     "完整的一份报告见下图。")
figure(ASSETS / "fig_ui_report.png",
       "图 3-6　看板中的诊断报告：#64 PortScan，五段齐全，底部是可继续追问的输入框")
body("这张截图里的报告是真实调用产生的，不是模板：底部标注“模型 deepseek-chat　耗时 4 933 ms”，"
     "正文 1 071 字，证据链里引用的“PSH Flag Count = 1.0，偏离训练分布 1.228 个标准差”"
     "直接来自 3.3.7 节的证据打包逻辑，处置建议里则出现了具体的网段与端口号。"
     "这几条细节说明它确实是“按给的证据写的”，而不是一篇通稿。")

h3("3.4.3 知识检索：为什么用 BM25 而不是向量库")
body("知识库只有 12 条协议知识（TCP 握手、SYN Flood、端口扫描、DoS Hulk、DDoS、暴力破解、Heartbleed、"
     "流特征语义、IAT 含义、误报、处置手册、抽样偏差），查询词就是固定的类别名加特征名。"
     "这个规模下向量检索并不比词面检索好，却要多装 torch、多下一个模型、多一个失效点；"
     "中文没有空格，按字切会把“端口扫描”切成四个没有意义的单字，所以用字符二元组。"
     "接口保持 retrieve(query, top_k)，将来要换向量库只需改 rag.py 一个文件。")
body("检索结果取 Top-3 拼进提示词。之所以不是 Top-5 或更多，是因为知识库总共只有 12 条，"
     "取太多会把无关条目塞进上下文，反而稀释了真正相关的那一两条；而且大模型对提示词里"
     "“哪段是证据、哪段是背景”的分辨能力有限，越长越容易串台。")

h3("3.4.4 降级路径与追问")
body("降级路径也做了：没有配置 API key、或网络请求失败时，系统生成模板版报告并在界面上明确标注，"
     "服务本身不因此不可用。这个设计有实际收益——本机环境里 ALL_PROXY 写成 socks:// 时，"
     "httpx 在构造 Client 时就会抛异常，如果不在这一层兜住，整个诊断链路会连带把上报接口拖垮。")
body("多轮追问复用同一套 schema：提问时携带上一轮的报告正文作为上下文，回答仍按五段落库，"
     "所以追问记录与首轮报告一样可检索、可导出。追问的设计意图是回答“换了前提会怎样”——"
     "例如“如果是内网主机被攻陷发起的，处置顺序有什么不同”，答案会重排处置建议的先后，"
     "而不是重复一遍报告。")

h3("3.4.5 数据集构建")
body("数据集抽样脚本按类配额抽取，并处理了两个必须处理的数据问题：一是原文件列名带前导空格"
     "（形如 ' Destination Port'），抽样时统一去掉，否则按下标取列会与按名取列得到不同结果；"
     "二是 Kaggle 镜像里三个 Web Attack 标签的 en dash 被上传者写坏成 U+FFFD（2 180 处，"
     "正好等于这三类的行数），它们不属于六类，抽取时已丢弃，labels.py 里的 normalize_label "
     "对这两个字符做了兼容。")
body("此外脚本写了两列元数据：__source__ 记录每行来自哪个原始 CSV，用于按天的跨天评估；"
     "__order__ 是全局时间序号，按“天 → 文件内行号”递增（文件名字母序不等于时间序），"
     "用于按类内时间留出。这两列在训练时会被剔除（双下划线开头一律不作特征），"
     "但它们是把“按时间划分”这件事做对的前提。")

h3("3.4.6 本部分完整代码")
body("以下为本部分全部代码。知识库 chunks.json 是结构化数据而不是程序，"
     "因此按字段拆成表 3-9 列出——每条的 id、标题、检索标签、正文与文件逐字段一致，"
     "直接读比读带转义的中文 JSON 更容易核对。")
code_file("llm/schema.py", "M4 输出解析与校验")
code_file("llm/prompts.py", "M4 提示词组装")
code_file("llm/client.py", "M4 大模型客户端与降级")
code_file("llm/rag.py", "M9 字符二元组 BM25 检索")
code_file("tools/build_sample.py", "数据集抽样与清洗")
code_file("tests/test_llm_and_center.py", "大模型层与中心接口联测")

_chunks = json.loads((ROOT / "data/rag/chunks.json").read_text(encoding="utf-8"))
table(
    ["编号", "标题", "检索标签", "正文"],
    [[c["id"], c["title"], "、".join(c["tags"]), c["text"]] for c in _chunks],
    widths=[2.2, 2.8, 2.6, 7.6],
    caption=f"表 3-9　M9 知识库全部 {len(_chunks)} 条内容（与 chunks.json 逐字段一致）",
    font_pt=8,
    left_cols=(0, 1, 2, 3),
)

h3("3.4.7 小结")
body("本部分交付了从“告警”到“报告”的完整路径，并且把这条路径上的每一步都做成了可检查的："
     "提示词里的三条铁律对应三个具体的失败模式，schema 校验对应“字段缺失即拒绝”，"
     "降级路径对应“大模型挂了服务不能挂”。实测单份报告中位耗时 4.97 秒、中位正文 1 122 字，"
     "报告里引用的证据都能回溯到特征值和规则命中记录。")
body("这一层能做的事情有明确边界：它不判断、不预测、不替代分类器。把边界写清楚，"
     "比让它“看起来更智能”更有价值——否则一旦它改判，整个系统的评测口径就散了。")


# ====================================================== 3.5 王储
h2("3.5 王储：可视化看板与阈值规则引擎（M5 / M11）")
body("本人负责“让人看见结果”和“让系统有确定性下限”两件事：四个标签页的看板、以及与小模型并跑的"
     "阈值规则引擎。另外负责全部单元测试。")
table(
    ["文件", "行数", "职责"],
    [
        ["dashboard/app.py", "445", "四个标签页、图表、局部自动刷新"],
        ["center/rules.py", "292", "单流规则 + 窗口规则 + 按域去重"],
        ["tools/rules_baseline.py", "109", "规则基线在与模型相同的测试集上评测"],
        ["tests/*.py", "649", "特征、规则、训练流水线、混合森林的单元测试"],
    ],
    widths=[5.0, 2.0, 8.2],
    caption="表 3-10　本部分涉及的源文件",
    left_cols=(0, 2),
)

h3("3.5.1 看板的信息架构")
body("看板有四个标签页，分别对应四类使用者的问题：现在网络里在发生什么（实时总览）、有哪些告警"
     "（告警）、这条告警为什么可疑（诊断报告）、上周三那次扫描是什么情况（历史查询）。"
     "四个标签页共用顶部的连接设置与统计时间范围，切换标签不重新输入。")
figure(ASSETS / "fig_ui_live.png",
       "图 3-7　实时总览：四个指标块、每 10 秒的流数量折线、判定分布与协议构成")
body("自动刷新是用 Streamlit 的 fragment 实现的：实时总览每 2 秒、告警页每 5 秒、报告页每 10 秒各自局部重渲，"
     "而不是整页重跑。这里踩过一个坑——最初在告警页里调用了 st.rerun(scope=\"app\")，"
     "那一刻会连实时页一起重跑，整页重跑会把标签页冲回第一个，于是用户每选一次告警就被弹回“实时总览”。"
     "改成只写 session_state、由报告页自己按 10 秒刷新之后，标签页才稳得住。")
figure(ASSETS / "fig_ui_alerts.png",
       "图 3-8　告警页：类别过滤、告警表（含来源与判定值）、告警类别分布")
body("告警表里有一列叫“判定值”，它的含义随来源变化：小模型的告警显示为百分比（100.0%），"
     "规则的告警显示为超阈值倍数（1.03×）。这两者不是同一种量，所以不在同一列里混着比大小，"
     "而是在表下用文字说明“规则不输出置信度”。图表也遵守同一条原则：颜色从不单独承载信息，"
     "所有柱状图都直接标数值，风险等级同时写文字。")
figure(ASSETS / "fig_ui_history.png",
       "图 3-9　历史查询：按探针、日期、类别过滤，结果可导出 CSV")
body("会话流水表只下发展示用的几个特征列，不下发 78 维整包——200 行整包会超过 1 MB，"
     "而看板要的是“看得懂”，不是“看得全”。要核查细节时按流标识回中心取原始记录，"
     "再回 pcap 里逐帧对照。")

h3("3.5.2 阈值规则引擎")
body("规则层不是“小模型的简化版”，它在系统里有两个独立用途：一是与机器学习同口径的确定性对照基线，"
     "二是线上兜底。判据分两组：单流规则只看一条流的特征（包长、时长、包数、标志位），"
     "阈值取自训练段各类的分位数；现场行为规则判的是窗口内的行为量（同一源在 60 秒内探了多少个不同目的端口、"
     "同一目的端口上未应答的 SYN 流有多少条），这类量不依赖采集口径，线上用它。")
body("两条实现约定需要交代。其一是去重按域而不按规则：一次 200 端口的扫描会同时命中 port_scan、"
     "portscan_short、scan_single 三条规则，若每条各报一次，看板就被刷满，“这是一次扫描”反而看不出来。"
     "所以扫描类共用一个按源 IP 的去重域，洪泛类按目的 IP:端口，每次只报一条、60 秒冷却。"
     "其二是规则不输出置信度：告警表里 source='rule' 的行，confidence 存的是“超出阈值多少倍”，不是概率，"
     "看板按“1.03×”这样的措辞展示，不与小模型的 0.996 并列比较。")
body("还有一条容易被忽略的约定：flow_rules() 返回的列表顺序就是优先级，pick() 取第一条，"
     "不按 strength 排序。原因是不同规则的“超出多少倍”之间没有可比性——"
     "超阈值 20 倍的端口扫描与超阈值 2 倍的洪泛，谁更严重取决于场景，不取决于倍数。")

h3("3.5.3 规则基线评测结果")
table(
    ["类别", "规则精确率", "规则召回率", "规则 F1", "小模型 F1"],
    [
        ["BENIGN", "0.633", "0.607", "0.620", "0.979"],
        ["DDoS", "0.919", "0.471", "0.623", "0.955"],
        ["DoS Hulk", "0.704", "0.256", "0.376", "0.954"],
        ["Patator", "0.500", "0.905", "0.644", "0.998"],
        ["PortScan", "0.468", "0.989", "0.635", "0.973"],
        ["macro-F1", "—", "—", "0.5795", "0.9719"],
    ],
    widths=[3.2, 3.0, 3.0, 3.0, 3.0],
    caption="表 3-11　阈值规则基线与小模型在同一段测试集上的对照（22 907 行）",
    bold_rows=(5,),
)
figure(ASSETS / "fig_rules.png", "图 3-10　规则基线评测脚本的实测输出（本机终端）")
body("0.5795 这个数要读对两件事。第一，它只是单流规则的成绩——每次判定只看得见一行特征。"
     "端口扫描真正依靠的是“同一源在窗口内探了多少个目的端口”，而这条信息在 CSV 里根本不存在"
     "（78 列特征里既没有源/目的 IP，也没有时间戳）。线上规则引擎用的是窗口判据，能力不止这个数，"
     "所以不能拿 0.5795 去证明“规则无用”。")
body("顺带一提，阈值规则作为端口扫描检测手段的局限性，在公开的实验评估里也有类似记录[17]——"
     "单流判据对“慢扫描”和“单包短流”这两端都不敏感，这和我们量到的 0.468 精确率是一致的。")
body("第二，规则在“小模型失效的那种形态”上确实工作。实测两条：25 条单包 SYN 探测流走完整链路，"
     "小模型 25 条全判 BENIGN，规则层出 1 条 PortScan 告警；把数据集里 3 条 PortScan 加 3 条 DoS Hulk 行"
     "喂进去，小模型出 6 条告警且每条都带六类概率，规则同时给其中 4 条补了印证命中。"
     "这正是开集问题下的分工：小模型管它见过的形态，规则管与采集口径无关的行为。")

h3("3.5.4 单元测试")
body("单元测试 59 条，以合成数据为主，刻意不依赖 CIC-IDS2017 原始文件，保证换一台机器 clone 下来即可跑。"
     "覆盖的重点是三类容易静默出错的地方：特征口径（包长只统计 L4 载荷、标志位是 0/1 而不是次数）、"
     "规则引擎（去重域、冷却、优先级顺序）、以及 schema 校验（字段缺失与风险等级越界必须拒绝）。")
figure(ASSETS / "fig_pytest.png", "图 3-11　单元测试：59 条全部通过")
body("测试的写法上也有一条经验：断言要指向“能力是否存在”，而不是“函数有没有被调用”。"
     "例如验证去重域时，断言的是“200 端口扫描只产生 1 条告警”，而不是“_should_report 被调用了 200 次”；"
     "后者在去重逻辑写错时同样可能通过。")

h3("3.5.5 本部分完整代码")
body("以下为本部分全部代码。测试文件按模块拆成四个，按“特征 → 规则 → 训练流水线 → 混合森林”排列。")
code_file("dashboard/app.py", "M5 看板")
code_file("center/rules.py", "M11 规则引擎")
code_file("tools/rules_baseline.py", "M11 规则基线评测")
code_file("tests/test_features.py", "特征口径回归测试")
code_file("tests/test_rules.py", "规则引擎测试")
code_file("tests/test_train_pipeline.py", "训练流水线测试")
code_file("tests/test_hybrid_forest.py", "混合森林测试")

h3("3.5.6 小结")
body("本部分交付了可用的界面与可对照的下限。看板的价值不在好看，而在于它把“来源”“判定值”“风险”"
     "这三种不同性质的量分开放置，让人一眼能分清哪条告警是模型给的、哪条是规则给的、"
     "哪条的数值是概率、哪条是超阈值的倍数。规则引擎的价值不在指标，而在于它提供了一条"
     "“不依赖采集口径”的兜底判据，并在小模型全判 BENIGN 的现场扫描流上确实报了警。")
body("单元测试 59 条不是凑数：其中三条直接钉住了 3.3.1 节里那两处口径错配，"
     "任何人改坏包长或标志位的统计方式，测试会立刻红。")


# ====================================================== 3.6 联调
h2("3.6 系统联调与总体验证")
body("四部分完成后由组长做端到端联调。链路是：回放脚本按 2 秒 2 条送会话 → 中心鉴权、推理、落库 →"
     "非 BENIGN 流升级成告警 → 规则引擎补充印证 → 后台调用大模型生成报告 → 看板展示。"
     "联调中出现的问题记在 3.7 节。")
body("下图是一次完整的接口联调，五个步骤串起来，全部为真实调用。")
figure(ASSETS / "fig_api.png",
       "图 3-12　端到端接口联调：健康检查 → 上报 → 查告警 → 取大模型报告 → 看统计")
body("这次联调里第四步的读数是：DeepSeek 耗时 4 933 ms、正文 1 071 字；第五步统计显示大模型累计调用 69 次、"
     "失败 0 次、可用。其中 #65 是规则命中的告警（来源 rule，超阈值 8.49 倍），#64 与 #63 是小模型判定的告警，"
     "三种来源在同一张表里靠“来源”列区分，不会混淆。")
body("联调还做了一次重复性验证：规则基线脚本重跑，准确率 0.6028、macro-F1 0.5795，与文档记录的数值逐位一致；"
     "五模型对比脚本重跑，表 3-6 与图 3-3 的输出一致。这两次重跑的意义在于确认“报告里的数字不是一次性的”——"
     "换一台机器、换一天，跑出来还是这些数。")
body("看板在浏览器里的实际使用也做了验收：实时页的折线随回放刷新，告警表每 5 秒出现新行，"
     "选中一条告警后报告页在 10 秒内出结果，追问的回答在整块重渲后仍在（存在 session_state 里）。"
     "这一组验收用的是真实操作截图（图 3-7 至图 3-9），不是示意图。")


# ====================================================== 3.7 问题
h2("3.7 遇到的问题与解决")
body("开发过程中影响较大的问题列在下表。挑选标准是“曾经让判据变绿但结论是错的”，"
     "纯粹的环境配置问题不在此列。")
table(
    ["现象", "根因", "处理"],
    [
        ["四个模型在 0.999 附近并列，XGBoost 与单棵决策树只差 0.0002",
         "CIC-IDS2017 随机划分把同一天的近似重复流同时分进训练与测试",
         "改用类内按时间划分，并对 9.7% 的完全重复行去重；0.999 不作为结论"],
        ["验证集上 random_forest 与 xgboost 并列，测试集上差 0.0243",
         "单段验证集紧贴训练段尾部，测不出再往后滑一段会不会失手",
         "改为前向滚动验证（3 折 expanding window），最后 10% 全程封存"],
        ["线上提取的向量与训练分布对不上，单包流包长被记成 40",
         "包长类列在数据集里是 L4 载荷字节，我们按 IP 总长统计",
         "按数据集口径改为只统计 L4 载荷，并补一条回归测试钉住"],
        ["200 包洪流的 Fwd PSH Flags 为 200，相对全表 z≈1006",
         "数据集的标志位列是 0/1 指示量（是否出现过），不是次数",
         "改为 0/1，并补一条回归测试钉住"],
        ["Heartbleed 类在测试集里 0 行，等于被抹掉",
         "全量里 Heartbleed 只有 11 行，按比例抽样后只剩 1 行",
         "改按类配额抽样、稀有类全收；同时说明这抬高了类别先验"],
        ["演示时一分钟内产生 21 条 PortScan 误报，触发 21 次大模型调用",
         "数据集的 BENIGN 行里约 48% 是单包短流，会命中 portscan_short 规则（该规则精确率仅 0.468）",
         "回放脚本在本地先用 flow_rules() 预筛 BENIGN 行（保留 400、跳过 365），"
         "并删除这 21 条误告警与报告"],
        ["服务起不来 / 报告全部退化为模板版",
         "本机 ALL_PROXY 与 all_proxy 均为 socks://，httpx 只认 socks5://，构造 Client 时即抛异常",
         "启动时 env -u ALL_PROXY -u all_proxy；探针对局域网中心设 trust_env=False；"
         "大模型层捕获后降级为模板报告"],
        ["XGBoost 训练直接报标签错误",
         "sklearn 接口只接受 0..K-1 的整数标签，predict() 返回的是下标",
         "统一编码一次，预测结果过 artifact[\"classes\"][pred] 还原类名"],
        ["切到告警标签页后约 9 秒被弹回第一个标签页",
         "告警页里调用了 st.rerun(scope=\"app\")，整页重跑重置了标签选择",
         "去掉该调用，改为写 session_state，由报告页按 10 秒自行刷新"],
        ["追问的回答刚一出现就消失",
         "报告页每 10 秒整块重渲，直接 st.success 的内容会被刷掉",
         "回答按 report_id 存进 session_state，重渲后仍能取回"],
        ["报告字段偶有缺失，模型输出不成结构",
         "大模型自由发挥，风险等级不在枚举内或缺少证据链",
         "用 Pydantic 强校验，字段缺失即拒绝落库并触发重试/降级"],
        ["连续攻击流量下大模型调用次数与告警数成正比",
         "中心对每条告警各排一次诊断任务，没有按类别或时间窗合并",
         "已在文档中记为已知问题；演示前先做误报预筛。后续应改为按类别合并、"
         "并设单位时间调用上限"],
    ],
    widths=[5.0, 5.4, 5.0],
    caption="表 3-12　开发中的主要问题与处理",
    font_pt=8.5,
    left_cols=(0, 1, 2),
)


# ====================================================== 3.8 结论
h2("3.8 结论与不足")

h3("3.8.1 做到了什么")
body("第一，四层链路在一台机器上完整跑通：从会话特征上报，到小模型判定并落库告警，到规则引擎补充印证，"
     "到大模型生成五段式中文报告，到看板实时展示与追问，全部是真实调用而非示意。"
     "单份报告的中位耗时 4.97 秒、中位正文 1 122 字。")
body("第二，给出了同口径、可复现的量化证据：五模型在同一次前向滚动验证与同一段封存测试集上对比，"
     "XGBoost 的 reliable macro-F1 为 0.9719；同一个测试段上阈值规则基线为 0.5795；"
     "两列数字来自同一批 22 907 行、同一 macro 口径，可以直接相减。")
body("第三，文档里每一条结论都写清了它成立的条件，包括那些对我们不利的结论：混合森林没有超过单模型、"
     "按天留出在六类模型上不可用、线上手工构造的流量被判成 BENIGN 0.9999。")

h3("3.8.2 没做到的与不敢说的")
bullet("（1）双探针联动（M10）未完成，只有设计没有联调，原因是第二台机器未到位。")
bullet("（2）真实抓包没有在答辩机上跑通。本机没有 CAP_NET_RAW 权限，演示用的是数据集回放走真实接口，"
       "被替换的只是“帧从哪里来”这一环。这项应当在有权限的机器上补做。")
bullet("（3）开集泛化没有解决，跨天留出实验是失败的。这是数据集的类别分布决定的（每类攻击只出现在某一天），"
       "不是调参能解决的事情，我们把它写成结论而不是掩盖。")
bullet("（4）没有做消融定位混合森林在 DoS Hulk 上掉到 0.629 的成因，只记录了现象。")
bullet("（5）大模型调用次数与告警数成正比，没有做合并与限流，连续攻击流量下会产生大量调用。")
bullet("（6）中心把推理与落库放在同一个进程里串行执行，没有消息队列缓冲，连续大流量下上报接口会被推理阻塞。"
       "两周周期内我们判断多一个中间件就多一个失效点，这个取舍在课程演示规模下成立，但不应被读成“已经够用”。")

h3("3.8.3 最重要的一条认识")
body("把在线提取器接到真实流量上、再回头核对数据集之后，我们得到的结论是：小模型学到的是这份数据集的"
     "判别边界，而不是这类攻击的判别边界。数据集自己的行没有问题——类内时间留出集上 PortScan 召回 0.998、"
     "DoS Hulk 0.913；但按数据集形态手工构造的一条 DoS Hulk 仍被判 BENIGN 0.9999，因为数据集里的流量是"
     "“长流慢速”（中位 84.9 秒、6 个包、0.16 包/秒），而我们现场构造的是“短流突发”（0.1 秒、200 个包、"
     "2 010 包/秒）。遇到没见过的形状时，小模型既不报警也不报错[16]。")
body("这条认识直接决定了系统的三层分工：小模型负责在已知形态里给出类别与置信度，用于方法验证与演示；"
     "规则引擎负责线上兜底，判的是与采集口径无关的行为量；大模型负责解释前两层说不清的流量。"
     "这也解释了为什么不能用一个“准确率 0.97”来总结这个项目——那个数字描述的是数据集内部的一致性，"
     "不是系统的线上能力。把这条边界讲清楚，比把指标报得更高更能说明我们明白自己在做什么。")

h3("3.8.4 后续工作")
body("按优先级排列：补做真实抓包与攻击复现的联动验证（需要 CAP_NET_RAW）；完成 M10 双探针演示；"
     "把大模型诊断改为按类别与时间窗合并、并加调用上限；尝试原始字节级的端到端检测（1D-CNN 直接读 pcap，"
     "绕过人工特征），这是让模型真正学会“攻击形态”而不是“数据集形态”的可行方向；"
     "把规则阈值改为可在线配置，减少每次调参都要重训重测的成本。")


# ----------------------------------------------------------------- 四、参考文献

h1("四、参考文献")

refs = [
    "[1] 谢希仁. 计算机网络（第 8 版）[M]. 北京: 电子工业出版社, 2022 年 1 月.",
    "[2] 袁华, 王昊翔, 黄敏. 深入理解计算机网络[M]. 北京: 清华大学出版社, 2024 年 5 月.",
    "[3] 唐继勇, 龙兴旺. 计算机网络基础[M]. 北京: 人民邮电出版社, 2024 年 8 月.",
    "[4] IETF. RFC 793: Transmission Control Protocol[S]. 1981.",
    "[5] IETF. RFC 5681: TCP Congestion Control[S]. 2009.",
    "[6] Sharafaldin I, Lashkari A H, Ghorbani A A. Toward Generating a New Intrusion Detection "
    "Dataset and Intrusion Traffic Characterization[C]//Proceedings of the 4th International "
    "Conference on Information Systems Security and Privacy (ICISSP). 2018: 108-116.",
    "[7] Lashkari A H, Draper-Gil G, Mamun M S I, et al. Characterization of Tor Traffic using "
    "Time based Features[C]//Proceedings of the 3rd International Conference on Information "
    "Systems Security and Privacy (ICISSP). 2017: 253-262.",
    "[8] Breiman L. Random Forests[J]. Machine Learning, 2001, 45(1): 5-32.",
    "[9] Chen T, Guestrin C. XGBoost: A Scalable Tree Boosting System[C]//Proceedings of the 22nd "
    "ACM SIGKDD International Conference on Knowledge Discovery and Data Mining. 2016: 785-794.",
    "[10] Ke G, Meng Q, Finley T, et al. LightGBM: A Highly Efficient Gradient Boosting Decision "
    "Tree[C]//Advances in Neural Information Processing Systems (NeurIPS). 2017: 3146-3154.",
    "[11] Prokhorenkova L, Gusev G, Vorobev A, et al. CatBoost: Unbiased Boosting with Categorical "
    "Features[C]//Advances in Neural Information Processing Systems (NeurIPS). 2018: 6638-6648.",
    "[12] Scapy 开发团队. Scapy 官方文档[EB/OL]. https://scapy.readthedocs.io/, 2024.",
    "[13] DeepSeek-AI. DeepSeek-V3 Technical Report[R]. arXiv:2412.19437, 2024.",
    "[14] Lewis P, Perez E, Piktus A, et al. Retrieval-Augmented Generation for Knowledge-Intensive "
    "NLP Tasks[C]//Advances in Neural Information Processing Systems (NeurIPS). 2020: 9459-9474.",
    "[15] Robertson S, Zaragoza H. The Probabilistic Relevance Framework: BM25 and Beyond[J]. "
    "Foundations and Trends in Information Retrieval, 2009, 3(4): 333-389.",
    "[16] Sommer R, Paxson V. Outside the Closed World: On Using Machine Learning for Network "
    "Intrusion Detection[C]//IEEE Symposium on Security and Privacy. 2010: 305-316.",
    "[17] Panjwani S, Tan S, Jarrin K M, et al. An Experimental Evaluation to Determine if "
    "Portscan Detectors are Effective for Zero-Day Scanning[C]//IEEE/IFIP International Conference "
    "on Dependable Systems and Networks (DSN). 2015: 211-222.",
]
for ref in refs:
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.line_spacing = 1.5
    pf.space_before = Pt(0)
    pf.space_after = Pt(2)
    pf.left_indent = Pt(24)
    pf.first_line_indent = Pt(-24)
    pf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    run_font(p.add_run(ref), SONG, 10.5, latin=TNR)


doc.save(OUT)
print("已生成:", OUT)
print("段落数:", len(doc.paragraphs), " 表格数:", len(doc.tables),
      " 代码清单数:", _code_no)
