"""M2 流量特征工程：把抓到的包聚成双向流，算出 CICFlowMeter 口径的 78 维特征。

为什么必须对着 CICFlowMeter 的口径复刻：模型是用 CIC-IDS2017 训的，那份数据由 CICFlowMeter
（Java 版）生成。字段名一样但定义不同，线上推理就是拿着分布不同的输入去问一个只在训练分布
上见过的模型——不会报错，只会静默误判。所以本文件逐字段对齐，并在有歧义的地方写明取舍。

口径约定（对应 CICFlowMeter 的实现）：

- **流的方向**由首个包决定。首个包的方向为 forward（fwd），反方向为 backward（bwd）。
  同一个五元组两个方向共用一个流对象，不拆成两条单向流。
- **时间单位**：Flow Duration、IAT、Active/Idle 全部是**微秒**，与数据集一致。
- **包长**用 IP 总长度（含 IP 头与传输层头），不是载荷长度。
- **Active/Idle**：包间隔 >= 5 s 视为进入空闲期，把流切成若干活跃期和空闲期，
  再对各自的长度做 Mean/Std/Max/Min。只有一个包时活跃期为 0。
- **Bulk 六个字段（Fwd/Bwd Avg Bytes/Packets/Bulk Rate）在 CIC-IDS2017 里恒为 0**，
  本项目实测确认（25 万行样本该六列唯一值只有 0），故输出 0.0 而不是另造一套定义。
- **Subflow 字段**：CICFlowMeter 把遇到 FIN/RST 就截止的一段算作一个 subflow。
  本实现一个流不拆分 subflow，因此 Subflow 数值等于整条流的累计值。
- **Fwd Header Length.1** 在原数据里是 "Fwd Header Length" 的重复列（实测逐行相等），输出同一个值。

本模块不依赖 scapy：抓包层把包解析成 PacketRecord 再喂进来，这样特征逻辑可以脱离
抓包权限、脱离真实网卡做单元测试。
"""

from __future__ import annotations

import math
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Iterable

# 78 维特征名，顺序必须与 models/artifacts/feature_schema.json 一致
FEATURE_ORDER = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

ACTIVE_TIMEOUT_S = 5.0     # 包间隔超过它就算进入空闲期
FLOW_TIMEOUT_S = 120.0     # 流整体过期时间，与 CICFlowMeter 一致

# TCP 标志位掩码
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80


@dataclass(frozen=True)
class PacketRecord:
    """抓包层解析出的最小事实集，特征逻辑只认这个，不认 scapy 的包对象。"""

    ts: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: int          # 6=TCP, 17=UDP
    length: int         # IP 总长度（含头）
    header_len: int     # IP 头 + 传输层头
    payload_len: int
    tcp_flags: int = 0
    tcp_window: int = -1
    tcp_header_len: int = -1


# 包长类特征一律取 payload_len 而不是 length。CIC-IDS2017 的 "Total Length of Fwd Packets"、
# "Fwd Packet Length Max"、"Average Packet Size" 在单个 SYN 上的取值是 0，在 SYN+6 字节应答上
# 是 6——它们统计的是 L4 载荷，不含 IP/TCP 头。拿 IP 总长度去算，同一份线上流量会得到
# "包长 40" 而不是 "包长 0"，训练时学到的阈值全部失配（改前实测：构造的 60 条扫描流全判 BENIGN）。


@dataclass
class FlowState:
    key: tuple
    start: float
    last: float
    fwd_ts: list = field(default_factory=list)
    bwd_ts: list = field(default_factory=list)
    fwd_len: list = field(default_factory=list)
    bwd_len: list = field(default_factory=list)
    fwd_hdr: int = 0
    bwd_hdr: int = 0
    flags: dict = field(default_factory=lambda: {
        "fin": 0, "syn": 0, "rst": 0, "psh": 0, "ack": 0, "urg": 0, "ece": 0, "cwr": 0,
        "fwd_psh": 0, "bwd_psh": 0, "fwd_urg": 0, "bwd_urg": 0,
    })
    init_win_fwd: int = -1
    init_win_bwd: int = -1
    act_data_fwd: int = 0
    min_seg_fwd: int = -1
    finished: bool = False

    def add(self, rec: PacketRecord, forward: bool) -> None:
        self.last = rec.ts
        if forward:
            self.fwd_ts.append(rec.ts)
            self.fwd_len.append(rec.payload_len)
            self.fwd_hdr += rec.header_len
            if self.init_win_fwd < 0 and rec.tcp_window >= 0:
                self.init_win_fwd = rec.tcp_window
            if rec.payload_len > 0:
                self.act_data_fwd += 1
            if rec.tcp_header_len > 0 and (
                self.min_seg_fwd < 0 or rec.tcp_header_len < self.min_seg_fwd
            ):
                self.min_seg_fwd = rec.tcp_header_len
        else:
            self.bwd_ts.append(rec.ts)
            self.bwd_len.append(rec.payload_len)
            self.bwd_hdr += rec.header_len
            if self.init_win_bwd < 0 and rec.tcp_window >= 0:
                self.init_win_bwd = rec.tcp_window

        f = rec.tcp_flags
        if f & FIN:
            self.flags["fin"] += 1
            self.finished = True
        if f & SYN:
            self.flags["syn"] += 1
        if f & RST:
            self.flags["rst"] += 1
            self.finished = True
        if f & PSH:
            self.flags["psh"] += 1
            self.flags["fwd_psh" if forward else "bwd_psh"] += 1
        if f & ACK:
            self.flags["ack"] += 1
        if f & URG:
            self.flags["urg"] += 1
            self.flags["fwd_urg" if forward else "bwd_urg"] += 1
        if f & ECE:
            self.flags["ece"] += 1
        if f & CWR:
            self.flags["cwr"] += 1


def _stats(values: list) -> tuple:
    """返回 (mean, std, max, min)。空列表返回全 0，避免 nan 进模型。"""
    n = len(values)
    if n == 0:
        return 0.0, 0.0, 0.0, 0.0
    mean = sum(values) / n
    var = sum((v - mean) ** 2 for v in values) / n  # 总体标准差，与 CICFlowMeter 一致
    return mean, math.sqrt(var), max(values), min(values)


def _bit(n: int) -> float:
    """标志位列一律输出 0/1。CIC-IDS2017 发布的 8 个 flag 列与 4 个 Fwd/Bwd Flags 列
    取值只有 0/1（`PSH Flag Count` 也是），不是"出现过几次"。我们按出现次数输出的话，
    一条 200 包的洪流会给出 200，而训练集里最大值是 1——z 分数上千，模型直接失效。"""
    return 1.0 if n > 0 else 0.0


def _iats(ts: list) -> list:
    """同一方向内相邻包的时间差（微秒）。不足两个包时为空。"""
    return [(b - a) * 1e6 for a, b in zip(ts, ts[1:])]


def _active_idle(ts: list) -> tuple:
    """把整条流按 5 s 间隔切成活跃期/空闲期，返回两组的时长列表（微秒）。"""
    if not ts:
        return [], []
    active, idle = [], []
    seg_start = ts[0]
    for prev, cur in zip(ts, ts[1:]):
        gap = cur - prev
        if gap >= ACTIVE_TIMEOUT_S:
            active.append((prev - seg_start) * 1e6)
            idle.append(gap * 1e6)
            seg_start = cur
    active.append((ts[-1] - seg_start) * 1e6)
    return active, idle


def flow_features(flow: FlowState, now: float | None = None) -> dict:
    """算出一条流的 78 维特征。now 用于给未结束的流算截止到此刻的时长。"""
    # 未结束的流用当前时刻兜底：否则一个还在跑的长连接时长恒为 0，
    # 速率类特征会被放大成天文数字（实测未兜底时 Flow Bytes/s 会出现 1e12 量级）。
    end = flow.last if flow.finished or now is None else max(now, flow.last)
    all_ts = sorted(flow.fwd_ts + flow.bwd_ts)
    all_len = flow.fwd_len + flow.bwd_len

    duration_us = max((end - flow.start) * 1e6, 1.0)  # 除以 0 会把速率撑成 inf
    duration_s = duration_us / 1e6
    total_bytes = sum(all_len)
    total_pkts = len(all_len)
    n_fwd, n_bwd = len(flow.fwd_ts), len(flow.bwd_ts)

    f_mean, f_std, f_max, f_min = _stats(flow.fwd_len)
    b_mean, b_std, b_max, b_min = _stats(flow.bwd_len)
    p_mean, p_std, p_max, p_min = _stats(all_len)
    fi_mean, fi_std, fi_max, fi_min = _stats(_iats(flow.fwd_ts))
    bi_mean, bi_std, bi_max, bi_min = _stats(_iats(flow.bwd_ts))
    ai_mean, ai_std, ai_max, ai_min = _stats(_iats(all_ts))
    active_periods, idle_periods = _active_idle(all_ts)
    act_mean, act_std, act_max, act_min = _stats(active_periods)
    idl_mean, idl_std, idl_max, idl_min = _stats(idle_periods)

    fwd_iats = _iats(flow.fwd_ts)
    bwd_iats = _iats(flow.bwd_ts)

    return {
        "Destination Port": float(flow.key[4]),
        "Flow Duration": duration_us,
        "Total Fwd Packets": float(n_fwd),
        "Total Backward Packets": float(n_bwd),
        "Total Length of Fwd Packets": float(sum(flow.fwd_len)),
        "Total Length of Bwd Packets": float(sum(flow.bwd_len)),
        "Fwd Packet Length Max": float(f_max),
        "Fwd Packet Length Min": float(f_min),
        "Fwd Packet Length Mean": f_mean,
        "Fwd Packet Length Std": f_std,
        "Bwd Packet Length Max": float(b_max),
        "Bwd Packet Length Min": float(b_min),
        "Bwd Packet Length Mean": b_mean,
        "Bwd Packet Length Std": b_std,
        "Flow Bytes/s": total_bytes / duration_s,
        "Flow Packets/s": total_pkts / duration_s,
        "Flow IAT Mean": ai_mean,
        "Flow IAT Std": ai_std,
        "Flow IAT Max": ai_max,
        "Flow IAT Min": ai_min,
        "Fwd IAT Total": float(sum(fwd_iats)),
        "Fwd IAT Mean": fi_mean,
        "Fwd IAT Std": fi_std,
        "Fwd IAT Max": fi_max,
        "Fwd IAT Min": fi_min,
        "Bwd IAT Total": float(sum(bwd_iats)),
        "Bwd IAT Mean": bi_mean,
        "Bwd IAT Std": bi_std,
        "Bwd IAT Max": bi_max,
        "Bwd IAT Min": bi_min,
        "Fwd PSH Flags": _bit(flow.flags["fwd_psh"]),
        "Bwd PSH Flags": _bit(flow.flags["bwd_psh"]),
        "Fwd URG Flags": _bit(flow.flags["fwd_urg"]),
        "Bwd URG Flags": _bit(flow.flags["bwd_urg"]),
        "Fwd Header Length": float(flow.fwd_hdr),
        "Bwd Header Length": float(flow.bwd_hdr),
        "Fwd Packets/s": n_fwd / duration_s,
        "Bwd Packets/s": n_bwd / duration_s,
        "Min Packet Length": float(p_min),
        "Max Packet Length": float(p_max),
        "Packet Length Mean": p_mean,
        "Packet Length Std": p_std,
        "Packet Length Variance": p_std ** 2,
        "FIN Flag Count": _bit(flow.flags["fin"]),
        "SYN Flag Count": _bit(flow.flags["syn"]),
        "RST Flag Count": _bit(flow.flags["rst"]),
        "PSH Flag Count": _bit(flow.flags["psh"]),
        "ACK Flag Count": _bit(flow.flags["ack"]),
        "URG Flag Count": _bit(flow.flags["urg"]),
        "CWE Flag Count": _bit(flow.flags["cwr"]),
        "ECE Flag Count": _bit(flow.flags["ece"]),
        "Down/Up Ratio": (n_bwd / n_fwd) if n_fwd else 0.0,
        "Average Packet Size": (total_bytes / total_pkts) if total_pkts else 0.0,
        "Avg Fwd Segment Size": (sum(flow.fwd_len) / n_fwd) if n_fwd else 0.0,
        "Avg Bwd Segment Size": (sum(flow.bwd_len) / n_bwd) if n_bwd else 0.0,
        "Fwd Header Length.1": float(flow.fwd_hdr),
        # 这六列在 CIC-IDS2017 里恒为 0（实测），输出 0 才是同一口径
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": float(n_fwd),
        "Subflow Fwd Bytes": float(sum(flow.fwd_len)),
        "Subflow Bwd Packets": float(n_bwd),
        "Subflow Bwd Bytes": float(sum(flow.bwd_len)),
        "Init_Win_bytes_forward": float(flow.init_win_fwd),
        "Init_Win_bytes_backward": float(flow.init_win_bwd),
        "act_data_pkt_fwd": float(flow.act_data_fwd),
        "min_seg_size_forward": float(flow.min_seg_fwd),
        "Active Mean": act_mean,
        "Active Std": act_std,
        "Active Max": act_max,
        "Active Min": act_min,
        "Idle Mean": idl_mean,
        "Idle Std": idl_std,
        "Idle Max": idl_max,
        "Idle Min": idl_min,
    }


class FlowTable:
    """双向流表：把逐包记录聚成流，按需吐出特征向量。

    淘汰策略：流数超过上限时踢最久没动的（OrderedDict + move_to_end 实现 LRU）。
    打流量的场景下这一步是必需的——扫描类攻击会瞬间造出上万个只发一个包的流。
    """

    def __init__(self, max_flows: int = 5000, flow_timeout: float = FLOW_TIMEOUT_S):
        self.max_flows = max_flows
        self.flow_timeout = flow_timeout
        self.flows: OrderedDict = OrderedDict()
        self.dropped = 0

    @staticmethod
    def key_of(rec: PacketRecord) -> tuple:
        return (rec.proto, rec.src_ip, rec.src_port, rec.dst_ip, rec.dst_port)

    @staticmethod
    def reverse_of(key: tuple) -> tuple:
        proto, sip, sport, dip, dport = key
        return (proto, dip, dport, sip, sport)

    def add(self, rec: PacketRecord) -> None:
        key = self.key_of(rec)
        rev = self.reverse_of(key)
        flow = self.flows.get(key)
        forward = True
        if flow is None:
            flow = self.flows.get(rev)
            if flow is not None:
                key, forward = rev, False
        if flow is None:
            flow = FlowState(key=key, start=rec.ts, last=rec.ts)
            self.flows[key] = flow
            forward = True
            if len(self.flows) > self.max_flows:
                self.flows.popitem(last=False)  # 最久没动的流被挤掉
                self.dropped += 1
        flow.add(rec, forward)
        self.flows.move_to_end(key)

    def expire(self, now: float, max_age: float | None = None) -> list:
        """取出已经结束（FIN/RST）、超时、或存活超过 max_age 的流，从表里移除并返回。

        max_age 是为实时检测加的：一条长连接的 TCP 流可能几十分钟不结束，
        等它自然结束再分类等于永远不分类。代价是这类流会被截断成若干段，
        每段的 Flow Duration / IAT 都只是真实值的一部分——报告里必须写明这一点。
        """
        out = []
        for key in list(self.flows):
            flow = self.flows[key]
            too_old = max_age is not None and (now - flow.start) > max_age
            if flow.finished or (now - flow.last) > self.flow_timeout or too_old:
                out.append(self.flows.pop(key))
        return out

    def snapshot(self, now: float) -> list:
        """取当前所有活跃流的特征快照，不删流。

        实时看板要的是"现在这一秒发生了什么"，而告警又必须等流结束才准；两者都要，
        所以既提供 snapshot（不破坏状态）又提供 expire（收尾）。
        """
        return [(f.key, flow_features(f, now)) for f in list(self.flows.values())]

    def evict_idle(self, before: float) -> int:
        n = 0
        for key in list(self.flows):
            if self.flows[key].last < before:
                self.flows.pop(key)
                n += 1
        return n


def to_vector(features: dict, names: Iterable[str] = None) -> list:
    """按给定列序把特征字典拍成向量。列序来自训练时的 feature_schema.json。"""
    names = list(names) if names is not None else FEATURE_ORDER
    missing = [n for n in names if n not in features]
    if missing:
        raise KeyError(f"特征提取器缺少训练用到的列：{missing[:5]}（共 {len(missing)} 列）")
    return [features[n] for n in names]


def replay(records: Iterable[PacketRecord], max_flows: int = 5000) -> list:
    """离线回放一串包记录，返回所有结束的流特征。用于 pcap 回放与自测。"""
    table = FlowTable(max_flows=max_flows)
    out = []
    last_ts = 0.0
    for rec in records:
        table.add(rec)
        last_ts = rec.ts
        for flow in table.expire(rec.ts):
            out.append((flow.key, flow_features(flow)))
    for flow in table.expire(last_ts + FLOW_TIMEOUT_S + 1):
        out.append((flow.key, flow_features(flow)))
    return out
