"""M2 特征提取器自测：列序、双向合并、速率兜底、活跃/空闲切分。"""

import json
import math
from pathlib import Path

import pytest

from probe.features import (
    ACK,
    FIN,
    FEATURE_ORDER,
    PSH,
    SYN,
    FlowTable,
    PacketRecord,
    flow_features,
    replay,
    to_vector,
)

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "models" / "artifacts" / "feature_schema.json"


def pkt(ts, src=("10.0.0.1", 50000), dst=("10.0.0.2", 80), length=60, payload=0,
        flags=SYN | ACK, proto=6, tcp_window=29200):
    """造一个包。默认值让调用处只写和本例有关的参数。"""
    return PacketRecord(
        ts=ts,
        src_ip=src[0], src_port=src[1], dst_ip=dst[0], dst_port=dst[1],
        proto=proto,
        length=length,
        header_len=40 if proto == 6 else 28,
        payload_len=payload,
        tcp_flags=flags,
        tcp_window=tcp_window,
        tcp_header_len=20 if proto == 6 else -1,
    )


def test_feature_order_matches_trained_schema():
    """回归：提取器和模型的特征列一旦错位，线上推理不会报错，只会静默误判。
    这个断言把"提取器口径"和"训练产物口径"绑在一起。"""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert FEATURE_ORDER == schema["feature_names"]
    assert len(set(FEATURE_ORDER)) == 78


def test_two_directions_merge_into_one_flow():
    table = FlowTable()
    table.add(pkt(1000.0, payload=100, flags=SYN))              # 首包定方向：1 -> 2 是 fwd
    table.add(pkt(1000.5, src=("10.0.0.2", 80), dst=("10.0.0.1", 50000), payload=500, flags=ACK))
    table.add(pkt(1001.0, payload=200, flags=PSH | ACK))

    assert len(table.flows) == 1
    flow = next(iter(table.flows.values()))
    feats = flow_features(flow)
    assert feats["Total Fwd Packets"] == 2
    assert feats["Total Backward Packets"] == 1
    assert feats["Destination Port"] == 80
    assert feats["Init_Win_bytes_forward"] == 29200
    assert feats["act_data_pkt_fwd"] == 2     # 两个 fwd 包都带载荷
    # 时长单位是微秒
    assert feats["Flow Duration"] == pytest.approx(1_000_000.0)


def test_packet_length_columns_count_l4_payload_only():
    """回归：CIC-IDS2017 的包长列统计的是 L4 载荷。一个 60 字节的纯 SYN（载荷 0）
    在数据集里是 "Packet Length Mean = 0"，用 IP 总长度算出来是 60——这一列错位
    会让线上每一条流的向量都落在训练分布之外（实测 z 分数十几到上千）。"""
    table = FlowTable()
    table.add(pkt(1000.0, length=60, payload=0, flags=SYN))
    feats = flow_features(next(iter(table.flows.values())))
    assert feats["Fwd Packet Length Max"] == 0.0
    assert feats["Packet Length Mean"] == 0.0
    assert feats["Average Packet Size"] == 0.0
    assert feats["Total Length of Fwd Packets"] == 0.0

    table = FlowTable()
    table.add(pkt(1000.0, length=100, payload=60, flags=PSH | ACK))
    feats = flow_features(next(iter(table.flows.values())))
    assert feats["Packet Length Mean"] == 60.0           # 100 字节的包里 40 字节是头
    assert feats["Total Length of Fwd Packets"] == 60.0


def test_flag_columns_are_indicators_not_counts():
    """回归：CIC-IDS2017 发布的 flag 列取值只有 0/1。按出现次数输出的话，
    一条 200 包的洪流给出 200，而训练集最大值是 1，等于把证据送到了模型没见过的区间。"""
    table = FlowTable()
    for i in range(200):
        table.add(pkt(1000.0 + i * 0.0002, flags=SYN))
    feats = flow_features(next(iter(table.flows.values())))
    assert feats["SYN Flag Count"] == 1.0
    assert feats["Total Fwd Packets"] == 200
    assert feats["PSH Flag Count"] == 0.0


def test_rate_features_stay_finite_for_single_packet_flow():
    """回归：时长为 0 时 Flow Bytes/s 会变成 inf。训练管道会把含 inf 的行整行丢掉，
    线上不会——它会把这个 inf 直接喂进模型。"""
    table = FlowTable()
    table.add(pkt(2000.0))
    feats = flow_features(next(iter(table.flows.values())))
    for name in ("Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s"):
        assert math.isfinite(feats[name]), f"{name} 不是有限值：{feats[name]}"


def test_iat_is_in_microseconds():
    table = FlowTable()
    table.add(pkt(3000.0))
    table.add(pkt(3000.25))   # 250 ms
    feats = flow_features(next(iter(table.flows.values())))
    assert feats["Flow IAT Max"] == pytest.approx(250_000.0)
    assert feats["Fwd IAT Total"] == pytest.approx(250_000.0)


def test_active_idle_split_on_five_second_gap():
    table = FlowTable()
    table.add(pkt(4000.0))
    table.add(pkt(4002.0))    # 同一活跃期，长 2 s
    table.add(pkt(4010.0))    # 间隔 8 s >= 5 s，进入空闲期
    feats = flow_features(next(iter(table.flows.values())))
    assert feats["Idle Max"] == pytest.approx(8_000_000.0)
    assert feats["Active Max"] == pytest.approx(2_000_000.0)


def test_fin_terminates_flow():
    table = FlowTable()
    table.add(pkt(5000.0, flags=FIN | ACK))
    done = table.expire(5000.0)
    assert len(done) == 1 and not table.flows
    assert flow_features(done[0])["FIN Flag Count"] == 1


def test_flow_table_evicts_least_recently_used():
    """回归：扫描类攻击会瞬间造出上万个单包流，不设上限会吃光内存。"""
    table = FlowTable(max_flows=3)
    for i in range(5):
        table.add(pkt(6000.0 + i, src=("10.0.0.1", 40000 + i)))
    assert len(table.flows) == 3
    assert table.dropped == 2


def test_snapshot_does_not_remove_flows():
    """"实时快照"和"流结束收尾"是两件事，快照若顺手删流，告警就永远等不到流结束。"""
    table = FlowTable()
    table.add(pkt(7000.0))
    table.snapshot(7001.0)
    assert len(table.flows) == 1
    assert len(table.expire(7002.0)) == 0


def test_to_vector_rejects_missing_column():
    from collections import OrderedDict

    feats = OrderedDict((name, 0.0) for name in FEATURE_ORDER)
    assert len(to_vector(feats)) == 78
    del feats["Flow Duration"]
    with pytest.raises(KeyError):
        to_vector(feats)


def test_replay_returns_all_flows():
    records = [
        pkt(8000.0, src=("10.0.0.1", 1111), flags=FIN | ACK),
        pkt(8001.0, src=("10.0.0.1", 2222), flags=FIN | ACK),
    ]
    flows = replay(records)
    assert len(flows) == 2
