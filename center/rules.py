"""M11 阈值规则引擎：与小模型并跑的确定性基线，也是线上兜底。

为什么要单独做一层：小模型是在 CIC-IDS2017 的**聚合形态**上学的，现场抓到的短流突发
落在训练分布之外时，它既不报警也不报错（实测见 docs/architecture.md「在线路径实测」）。
规则层判的是行为——同一源在短窗口内探了多少个端口、同一目的端口撞了多少次半连接——
这些量不依赖包长/标志位的采集口径，所以能覆盖小模型看不见的形态。

两层：
  flow_rules()  单流规则，只看这一条流的特征。离线基线（tools/rules_baseline.py）用它，
                数据集 CSV 没有时间戳和跨流上下文，只能评这一层。
  RuleEngine    在线引擎 = 单流规则 + 窗口规则（按源 IP / 目的端口索引的滑动窗口）。
                两者共用一套去重域，见 SCOPE_OF。

**规则不输出"置信度"。** `RuleHit.strength` 是"实测值 ÷ 阈值"，只表示超阈值多少倍，
不是概率。告警表里 `source='rule'` 的行按这个字段展示，看板也照这个措辞写，
别把它混进与小模型的置信度对比里。
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Mapping

# 单流规则阈值。分两组：
# ① 「数据集口径」的判别阈值，取自训练段（前 70%）各类的分位数，在测试段上评一次
#    （tools/rules_baseline.py）。改之前先重跑那个脚本，否则报告里的对照数字就对不上了。
# ② 「现场口径」的行为阈值，判的是速率/包数这类不依赖采集方式的量，线上用。
PORTSCAN_MAX_DURATION = 1_000.0        # 微秒：端口扫描的单行流时长在 50 µs 量级
DDOS_BWD_BYTES = 5_000.0
DDOS_MAX_DURATION = 5e6                # 5 s
HULK_MIN_DURATION = 1e7                # 10 s
HULK_MIN_FWD_PKTS = 5.0
PATATOR_MIN_FWD = 9.0
PATATOR_MIN_BWD = 15.0
PATATOR_MIN_DURATION = 1e6             # 1 s

FLOOD_PPS = 1000.0                     # Flow Packets/s
FLOOD_FWD_PKTS = 100.0
SCAN_MAX_FWD_PKTS = 2.0
HEARTBLEED_BWD_BYTES = 1000.0
HEARTBLEED_MAX_PKTS = 3.0

# 窗口规则阈值
WINDOW_S = 60.0
PORT_SCAN_PORTS = 20        # 同一源在窗口内探过的不同目的端口数
PORT_SCAN_MAX_PKTS = 3.0    # 只把极短流算作探测
SYN_FLOOD_CONNS = 50        # 同一目的端口上 SYN 置位、ACK 未置位的流数
BRUTE_SHORT_PKTS = 12.0     # Patator 每次连接都很短：握手 + 一次认证 ≈ 10 个包
BRUTE_CONNS = 30


# 去重域：同类判据落进同一个域，一次扫描/一次洪泛只报一条。
# 值里 "scan" 按源 IP 归并，其余按目的（IP:端口）归并。
SCOPE_OF = {
    "port_scan": "scan",
    "portscan_short": "scan",
    "scan_single": "scan",
    "flood_single": "flood",
    "hulk_long": "flood",
    "ddos_burst": "flood",
    "syn_flood": "flood",
    "patator_short": "brute",
    "brute_force": "brute",
}


@dataclass(frozen=True)
class RuleHit:
    rule: str
    category: str
    observed: float
    threshold: float
    detail: str

    @property
    def strength(self) -> float:
        return self.observed / self.threshold if self.threshold else 0.0

    def as_evidence(self) -> dict:
        """塞进告警 evidence 列表的形态。带 detail，报告侧按它措辞而不是按 z 分数。"""
        return {
            "feature": f"规则 {self.rule}",
            "value": round(self.observed, 3),
            "detail": f"{self.detail}（阈值 {self.threshold:g}，实测 {self.observed:g}）",
        }


def _num(feats: Mapping[str, float], name: str) -> float:
    try:
        return float(feats.get(name, 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def flow_rules(feats: Mapping[str, float]) -> list[RuleHit]:
    """单流规则。**列表顺序就是优先级**，pick() 取第一条，别改成按强度选——
    不同规则的"超出多少倍"之间没有可比性。"""
    dur = _num(feats, "Flow Duration")
    fwd = _num(feats, "Total Fwd Packets")
    bwd = _num(feats, "Total Backward Packets")
    pps = _num(feats, "Flow Packets/s")
    syn = _num(feats, "SYN Flag Count")
    ack = _num(feats, "ACK Flag Count")
    bwd_bytes = _num(feats, "Total Length of Bwd Packets")

    hits = []
    if fwd >= PATATOR_MIN_FWD and bwd >= PATATOR_MIN_BWD and dur >= PATATOR_MIN_DURATION:
        hits.append(RuleHit(
            "patator_short", "Patator", fwd + bwd, PATATOR_MIN_FWD + PATATOR_MIN_BWD,
            f"单流 {fwd:g} 前向 / {bwd:g} 后向包，符合暴力破解反复短连接",
        ))
    if bwd_bytes >= DDOS_BWD_BYTES and 0 < dur <= DDOS_MAX_DURATION:
        hits.append(RuleHit(
            "ddos_burst", "DDoS", bwd_bytes, DDOS_BWD_BYTES,
            f"单流在 {dur / 1e6:.2f} 秒内取回 {bwd_bytes:g} 字节，密度异常",
        ))
    if dur >= HULK_MIN_DURATION and fwd >= HULK_MIN_FWD_PKTS and bwd_bytes >= DDOS_BWD_BYTES:
        hits.append(RuleHit(
            "hulk_long", "DoS Hulk", dur / 1e6, HULK_MIN_DURATION / 1e6,
            f"单流持续 {dur / 1e6:.1f} 秒、{fwd:g} 个前向包，符合慢速持续占用",
        ))
    if dur <= PORTSCAN_MAX_DURATION and fwd <= 2 and bwd <= 2:
        hits.append(RuleHit(
            "portscan_short", "PortScan", PORTSCAN_MAX_DURATION / max(dur, 1.0), 1.0,
            f"单行流时长 {dur:g} 微秒、{fwd:g} 个前向包，符合端口探测",
        ))
    if fwd >= FLOOD_FWD_PKTS and pps >= FLOOD_PPS:
        hits.append(RuleHit(
            "flood_single", "DoS Hulk", pps, FLOOD_PPS,
            f"单流 {fwd:g} 个前向包、{pps:g} 包/秒，超过洪泛阈值",
        ))
    if fwd <= SCAN_MAX_FWD_PKTS and bwd == 0 and syn >= 1 and ack == 0:
        hits.append(RuleHit(
            "scan_single", "PortScan", SCAN_MAX_FWD_PKTS - fwd + 1, 1.0,
            f"单包 SYN 且无应答（前向 {fwd:g} 包、后向 0 包）",
        ))
    if bwd_bytes >= HEARTBLEED_BWD_BYTES and bwd <= HEARTBLEED_MAX_PKTS and fwd <= HEARTBLEED_MAX_PKTS:
        hits.append(RuleHit(
            "heartbleed_single", "Heartbleed", bwd_bytes, HEARTBLEED_BWD_BYTES,
            f"极少包数换回 {bwd_bytes:g} 字节后向载荷，符合心跳响应过量读取",
        ))
    return hits


def pick(hits) -> RuleHit | None:
    """取优先级最高（列表最前）的那条。规则之间没有通用量纲，不能按 strength 比大小。"""
    return hits[0] if hits else None


class RuleEngine:
    """窗口规则。**有状态**，一个探针一份实例（内部按 probe_id 分域）。

    去重：同一条规则在同一个作用域上，`cooldown` 秒内只报一次。否则一次 5000 端口的扫描
    会给每条流都生成一条告警，看板会被淹没，反而看不出"这是一次扫描"。
    """

    def __init__(self, *, window: float = WINDOW_S, cooldown: float | None = None,
                 port_scan_ports: int = PORT_SCAN_PORTS,
                 port_scan_max_pkts: float = PORT_SCAN_MAX_PKTS,
                 syn_flood_conns: int = SYN_FLOOD_CONNS,
                 brute_conns: int = BRUTE_CONNS,
                 max_scope: int = 20000):
        self.window = window
        self.cooldown = window if cooldown is None else cooldown
        self.port_scan_ports = port_scan_ports
        self.port_scan_max_pkts = port_scan_max_pkts
        self.syn_flood_conns = syn_flood_conns
        self.brute_conns = brute_conns
        self.max_scope = max_scope
        self._src: OrderedDict[str, deque] = OrderedDict()
        self._dst: OrderedDict[str, deque] = OrderedDict()
        self._fired: dict[tuple, float] = {}
        self.counts: dict[str, int] = {}
        self.by_category: dict[str, int] = {}

    # ---------------------------------------------------------------- 内部

    @staticmethod
    def _trim(dq: deque, cutoff: float) -> None:
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def _bucket(self, store: OrderedDict, key: str, cutoff: float) -> deque:
        dq = store.get(key)
        if dq is None:
            dq = deque()
            store[key] = dq
            while len(store) > self.max_scope:
                store.popitem(last=False)
        else:
            store.move_to_end(key)
        self._trim(dq, cutoff)
        return dq

    def _should_report(self, scope: tuple, ts: float) -> bool:
        last = self._fired.get(scope)
        if last is not None and ts - last < self.cooldown:
            return False
        self._fired[scope] = ts
        if len(self._fired) > self.max_scope * 2:
            # 冷却表本身也要有上限，否则长跑之后只增不减
            cutoff = ts - self.cooldown
            self._fired = {k: v for k, v in self._fired.items() if v >= cutoff}
        return True

    def _scope(self, probe_id: str, rule: str, src_key: str, dst_key: str) -> tuple:
        """去重域。同类判据共用一个域：一次 200 端口的扫描会同时命中 port_scan、
        portscan_short、scan_single 三条规则，若每条各报一次，看板依然会被刷满。"""
        kind = SCOPE_OF.get(rule, rule)
        return (probe_id, kind, src_key if kind == "scan" else dst_key)

    # ---------------------------------------------------------------- 对外

    def observe(self, probe_id: str, ts: float, flow_key: str, feats: Mapping[str, float]) -> list[RuleHit]:
        """喂一条流，返回它触发的规则（已按去重域做冷却）。"""
        hits = []
        cutoff = ts - self.window

        parts = flow_key.split("|")
        if len(parts) < 5:
            return hits
        _proto, src_ip, _src_port, dst_ip, dst_port_raw = parts[:5]
        try:
            dst_port = int(dst_port_raw)
        except ValueError:
            dst_port = -1

        src_key = f"{probe_id}|{src_ip}"
        dst_key = f"{probe_id}|{dst_ip}|{dst_port}"

        fwd = _num(feats, "Total Fwd Packets")
        bwd = _num(feats, "Total Backward Packets")
        syn = _num(feats, "SYN Flag Count")
        ack = _num(feats, "ACK Flag Count")

        # 端口扫描：同一源、窗口内的**不同目的端口**数
        dq = self._bucket(self._src, src_key, cutoff)
        dq.append((ts, dst_port, fwd))
        ports = {p for (_t, p, f) in dq if f <= self.port_scan_max_pkts}
        if len(ports) >= self.port_scan_ports:
            if self._should_report(self._scope(probe_id, "port_scan", src_key, dst_key), ts):
                hits.append(RuleHit(
                    "port_scan", "PortScan", float(len(ports)), float(self.port_scan_ports),
                    f"源 {src_ip} 在 {self.window:g} 秒内探了 {len(ports)} 个不同目的端口",
                ))

        # 单流规则同样走去重域：一次洪泛里每条流都命中，不去重会把看板刷满
        for hit in flow_rules(feats):
            if self._should_report(self._scope(probe_id, hit.rule, src_key, dst_key), ts):
                hits.append(hit)

        # 同一目的端口上的连接激增：用 SYN 是否被应答区分半连接与完整连接
        dq2 = self._bucket(self._dst, dst_key, cutoff)
        syn_only = syn >= 1 and ack == 0
        dq2.append((ts, syn_only, fwd + bwd <= BRUTE_SHORT_PKTS))

        if syn_only:
            n = sum(1 for (_t, s, _short) in dq2 if s)
            if n >= self.syn_flood_conns and self._should_report(
                self._scope(probe_id, "syn_flood", src_key, dst_key), ts
            ):
                hits.append(RuleHit(
                    "syn_flood", "DDoS", float(n), float(self.syn_flood_conns),
                    f"目的 {dst_ip}:{dst_port} 在 {self.window:g} 秒内收到 {n} 条未应答的 SYN 流",
                ))
        else:
            n = sum(1 for (_t, s, short) in dq2 if not s and short)
            if n >= self.brute_conns and self._should_report(
                self._scope(probe_id, "brute_force", src_key, dst_key), ts
            ):
                hits.append(RuleHit(
                    "brute_force", "Patator", float(n), float(self.brute_conns),
                    f"目的 {dst_ip}:{dst_port} 在 {self.window:g} 秒内发生 {n} 次短连接，符合暴力破解",
                ))

        for hit in hits:
            self.counts[hit.rule] = self.counts.get(hit.rule, 0) + 1
            self.by_category[hit.category] = self.by_category.get(hit.category, 0) + 1
        return hits

    def hits_by_category(self) -> dict:
        return dict(self.by_category)

    def stats(self) -> dict:
        return {
            "window_s": self.window,
            "tracked_sources": len(self._src),
            "tracked_destinations": len(self._dst),
            "hits": dict(self.counts),
            "by_category": dict(self.by_category),
        }
