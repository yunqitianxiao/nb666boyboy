"""M11 规则引擎自测：单流规则、窗口规则、去重与内存上限。

这些断言都刻意配一组"刚好不够阈值"的对照，否则只测"能报"会漏掉阈值写反的情况。
基准流是一条约 0.3 秒、双向都有包的正常 TCP 会话，各用例只覆盖自己关心的字段。
"""

from probe.features import FEATURE_ORDER

from center.rules import RuleEngine, flow_rules, pick

# 正常会话基准：时长 0.3 s、4 前向 / 3 后向包、带 SYN 与 ACK
BASE = {name: 0.0 for name in FEATURE_ORDER}
BASE.update({
    "Flow Duration": 300_000.0,
    "Total Fwd Packets": 4.0,
    "Total Backward Packets": 3.0,
    "SYN Flag Count": 1.0,
    "ACK Flag Count": 2.0,
    "Flow Packets/s": 23.3,
})


def feats(**kw) -> dict:
    f = dict(BASE)
    f.update(kw)
    return f


def key(src="10.0.0.1", sport=40000, dst="10.0.0.2", dport=80, proto=6) -> str:
    return f"{proto}|{src}|{sport}|{dst}|{dport}"


# ---------------------------------------------------------------- 单流规则


def test_normal_web_flow_triggers_nothing():
    assert flow_rules(feats()) == []


def test_flood_needs_both_rate_and_packet_count():
    hits = flow_rules(feats(**{"Total Fwd Packets": 500, "Flow Packets/s": 5000}))
    assert "flood_single" in [h.rule for h in hits]
    # 只有包数没有速率：慢速大传输，不该报洪泛
    assert "flood_single" not in [h.rule for h in
                                  flow_rules(feats(**{"Total Fwd Packets": 500, "Flow Packets/s": 5}))]
    # 只有速率没有包数：一条 SYN 也能算出巨大速率（时长为 0 的兜底），不该报
    assert "flood_single" not in [h.rule for h in
                                  flow_rules(feats(**{"Total Fwd Packets": 1, "Flow Packets/s": 5000}))]


def test_lone_unanswered_syn_is_a_scan_probe():
    hits = flow_rules(feats(**{"Total Fwd Packets": 1, "Total Backward Packets": 0,
                               "SYN Flag Count": 1, "ACK Flag Count": 0}))
    assert "scan_single" in [h.rule for h in hits]
    assert pick(hits).category == "PortScan"
    # 同一个 SYN，但被应答过（ACK 置位）就不是探测
    assert "scan_single" not in [h.rule for h in flow_rules(
        feats(**{"Total Fwd Packets": 1, "Total Backward Packets": 0,
                 "SYN Flag Count": 1, "ACK Flag Count": 1}))]


def test_zero_duration_micro_flow_counts_as_probe():
    """数据集口径：PortScan 的单行流时长在 50 微秒量级、只有一两个包。"""
    hits = flow_rules(feats(**{"Flow Duration": 49.0, "Total Fwd Packets": 1,
                               "Total Backward Packets": 1}))
    assert pick(hits).category == "PortScan"


# ---------------------------------------------------------------- 窗口规则


def probe(**kw) -> dict:
    """窗口用例用：必须是"短但不是单包 SYN"的流，否则会被单流规则一起命中。"""
    f = feats(**{"Total Fwd Packets": 2, "Total Backward Packets": 1,
                 "SYN Flag Count": 1, "ACK Flag Count": 1})
    f.update(kw)
    return f


def test_port_scan_fires_on_the_twentieth_distinct_port():
    engine = RuleEngine(window=60.0)
    t = 1_000_000.0
    for i in range(19):     # 19 个端口：还差一个
        assert engine.observe("p1", t, key(dport=1000 + i), probe()) == []
    hits = engine.observe("p1", t, key(dport=1019), probe())
    assert [h.rule for h in hits] == ["port_scan"]
    assert hits[0].observed == 20.0


def test_port_scan_lookback_window_expires_old_probes():
    engine = RuleEngine(window=60.0)
    for i in range(19):
        engine.observe("p1", 1000.0, key(dport=1000 + i), probe())
    # 61 秒之后剩下的 19 条全部过期，重新计数
    assert engine.observe("p1", 1061.0, key(dport=2000), probe()) == []


def test_window_rule_reports_once_per_cooldown():
    """一次 200 端口的扫描只该生成一条告警，否则看板会被刷满、反而看不出是一次扫描。"""
    engine = RuleEngine(window=60.0)
    fired = 0
    for i in range(200):
        hits = engine.observe("p1", 1000.0 + i * 0.01, key(dport=1000 + i), probe())
        fired += sum(1 for h in hits if h.rule == "port_scan")
    assert fired == 1


def test_syn_flood_and_brute_force_are_told_apart_by_handshake():
    flood = RuleEngine(window=60.0)
    for i in range(50):
        # SYN 置位、ACK 未置位 → 半连接
        flood.observe("p1", 2000.0 + i * 0.01, key(dport=443, sport=50000 + i),
                      feats(**{"Total Fwd Packets": 1, "Total Backward Packets": 0,
                               "SYN Flag Count": 1, "ACK Flag Count": 0}))
    assert flood.counts.get("syn_flood") == 1
    assert flood.hits_by_category().get("DDoS") == 1

    brute = RuleEngine(window=60.0)
    hits = []
    for i in range(30):
        # 握手完成、连接很短 → 暴力破解
        hits = brute.observe("p1", 3000.0 + i * 0.01, key(dport=22, sport=60000 + i),
                             feats(**{"Total Fwd Packets": 6, "Total Backward Packets": 4,
                                      "SYN Flag Count": 1, "ACK Flag Count": 3}))
    assert "brute_force" in [h.rule for h in hits]
    assert {h.category for h in hits} == {"Patator"}


def test_engine_separates_probes():
    """两个探针各自看到自己那部分流量，计数不能混在一起。"""
    engine = RuleEngine(window=60.0)
    for i in range(15):
        engine.observe("p1", 4000.0, key(dport=1000 + i), probe())
    for i in range(15):
        assert engine.observe("p2", 4000.0, key(dport=1000 + i), probe()) == []


def test_tracked_sources_are_bounded():
    """扫描会瞬间造出大量源；不设上限内存会一直涨。"""
    engine = RuleEngine(window=60.0, max_scope=10)
    for i in range(50):
        engine.observe("p1", 5000.0, key(src=f"10.0.1.{i}", dport=80), probe())
    assert len(engine._src) <= 10


def test_evidence_carries_wording_not_z_score():
    hit = pick(flow_rules(feats(**{"Total Fwd Packets": 500, "Flow Packets/s": 5000})))
    ev = hit.as_evidence()
    assert "detail" in ev and "阈值" in ev["detail"]
    assert "z_score" not in ev
