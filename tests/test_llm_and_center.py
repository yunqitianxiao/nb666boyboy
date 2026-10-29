"""大模型层与中心端自测：输出结构、检索、推理契约、存储往返。

不联网：LLM 客户端只测解析与降级路径，不测真实调用。
"""

import json
from pathlib import Path

import numpy as np
import pytest

from center.database import FLOW_DISPLAY_FIELDS, Store
from center.inference import Detector, escalate
from llm.rag import Retriever, tokenize
from llm.schema import parse_diagnosis, validate, RISK_LEVELS
from probe.features import FEATURE_ORDER

ROOT = Path(__file__).resolve().parent.parent
MODEL = ROOT / "models" / "artifacts" / "best_model.pkl"
SCHEMA = ROOT / "models" / "artifacts" / "feature_schema.json"
CHUNKS = ROOT / "data" / "rag" / "chunks.json"


# ------------------------------------------------------------------ 输出结构


def test_parse_handles_fenced_json_and_surrounding_prose():
    text = '好的，报告如下：\n```json\n{"summary":"端口扫描","risk":"high",' \
           '"evidence":["RST 计数高"],"actions":["封禁源 IP"],"principle":"扫描利用半开连接"}\n```\n以上。'
    d = parse_diagnosis(text)
    assert d.summary == "端口扫描"
    assert d.risk == "high"
    assert d.evidence and d.actions and d.principle
    assert validate(d) == []


def test_unknown_risk_word_is_normalized_to_enum():
    """回归：模型写成"中高危"这类不在枚举里的值时，看板的颜色映射会静默失效。"""
    d = parse_diagnosis('{"summary":"x","risk":"中高危","evidence":["a"],"actions":["b"],"principle":"c"}')
    assert d.risk in RISK_LEVELS
    assert d.risk == "high"


def test_validate_reports_missing_sections():
    d = parse_diagnosis('{"summary":"","risk":"low","evidence":[],"actions":[],"principle":""}')
    problems = validate(d)
    assert len(problems) == 4


def test_markdown_has_all_five_sections():
    d = parse_diagnosis(
        '{"summary":"s","risk":"high","evidence":["e"],"actions":["a"],"principle":"p"}'
    )
    md = d.to_markdown()
    for title in ("事件概述", "风险等级", "证据链", "处置建议", "协议原理回顾"):
        assert title in md


# ------------------------------------------------------------------ 检索


def test_chinese_tokenizer_uses_bigrams():
    tokens = tokenize("端口扫描")
    assert "端口" in tokens and "扫描" in tokens
    assert "端" not in tokens  # 单字不参与，避免噪声


def test_retrieval_finds_the_right_chunk():
    r = Retriever(str(CHUNKS))
    for query, expect in [
        ("端口扫描 大量 RST 目的端口分散", "port-scan"),
        ("SYN 洪泛 半连接队列", "syn-flood"),
        ("暴力破解 SSH 认证失败", "brute-force"),
    ]:
        got = [c["id"] for c in r.retrieve(query, top_k=3)]
        assert expect in got, f"{query} 没检索到 {expect}，实际 {got}"


def test_retrieval_returns_empty_for_empty_query():
    r = Retriever(str(CHUNKS))
    assert r.retrieve("", top_k=3) == []


# ------------------------------------------------------------------ 推理契约


@pytest.fixture(scope="module")
def detector():
    if not MODEL.exists():
        pytest.skip("还没有训练产物，先跑 models/train.py")
    return Detector(str(MODEL), str(SCHEMA))


def test_detector_rejects_reordered_features(detector):
    """回归：列序错了不会报错，只会把"目的端口"当"流时长"去推理。必须当场拒收。"""
    bad = list(reversed(detector.feature_names))
    with pytest.raises(ValueError):
        detector.check_features(bad)
    detector.check_features(detector.feature_names)  # 正确列序不抛


def test_predict_batch_returns_class_names_not_indices(detector):
    x = np.zeros((3, len(detector.feature_names)))
    out = detector.predict_batch(x)
    assert len(out) == 3
    for row in out:
        assert row["category"] in detector.classes
        assert 0.0 <= row["confidence"] <= 1.0
        assert row["risk"] in ("info", "low", "medium", "high", "critical")
        assert pytest.approx(sum(row["proba"].values()), abs=1e-4) == 1.0


def test_top_features_returns_k_items(detector):
    x = np.zeros(len(detector.feature_names))
    items = detector.top_features(x, k=5)
    assert len(items) == 5
    assert all("feature" in it and "z_score" in it for it in items)


def test_escalate_respects_confidence():
    assert escalate("high", 0.999) == "critical"
    assert escalate("high", 0.90) == "high"
    assert escalate("high", 0.30) == "medium"


# ------------------------------------------------------------------ 存储


def test_store_roundtrip(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    fid = store.add_flow("probe-a", 1.0, 2.0, "6|1.1.1.1|1|2.2.2.2|80", "PortScan", 0.9, {"x": 1})
    aid = store.add_alert("probe-a", "6|1.1.1.1|1|2.2.2.2|80", "PortScan", 0.9, "high",
                          {"x": 1}, [{"feature": "SYN Flag Count", "value": 5}])
    rid = store.add_report(aid, "### 事件概述\n扫描", "deepseek-chat", 120)

    assert fid and aid and rid
    alert = store.alert(aid)
    assert alert["category"] == "PortScan"
    assert alert["evidence"][0]["feature"] == "SYN Flag Count"   # JSON 已还原成对象
    assert store.report_for_alert(aid)["content"].startswith("### 事件概述")

    st = store.stats(since=0)
    assert st["total_flows"] == 1
    assert st["by_prediction"] == {"PortScan": 1}
    assert st["by_protocol"] == {"6": 1}


def test_store_report_is_json_decoded_not_string(tmp_path):
    """回归：features/evidence 存的是 JSON 文本，读出来不还原就等于看板拿不到证据。"""
    store = Store(str(tmp_path / "t2.db"))
    store.add_alert("p", "k", "DDoS", 0.8, "high", {"a": 1}, [{"b": 2}])
    row = store.alerts(limit=1)[0]
    assert isinstance(row["features"], dict)
    assert isinstance(row["evidence"], list)


def test_flow_list_keeps_only_display_fields(tmp_path):
    """回归：流水表接口若不裁剪特征，200 行响应会到 MB 级，看板每 2 s 拉一次会拖死浏览器。"""
    store = Store(str(tmp_path / "t3.db"))
    feats = {name: i * 1.0 for i, name in enumerate(FEATURE_ORDER)}
    store.add_flow("probe-a", 1.0, 2.0, "6|1.1.1.1|5000|2.2.2.2|80", "BENIGN", 0.98, feats)

    row = store.flows(limit=1)[0]
    assert "features" not in row
    assert row["summary"]["Flow Duration"] == feats["Flow Duration"]
    assert set(row["summary"]) <= set(FLOW_DISPLAY_FIELDS)
    assert len(row["summary"]) < len(FEATURE_ORDER) / 10


# ------------------------------------------------------------------ 看板助手


def test_assistant_prompt_carries_snapshot_and_only_recent_turns():
    """助手最容易犯的两个错：忽略快照自己编数字、把整段超长对话塞进提示词。"""
    from llm.prompts import build_assistant

    history = [{"role": "user", "content": f"第{i}轮"} for i in range(20)]
    prompt = build_assistant(["流总数：10", "告警数：2"], history, "现在多少条？")
    assert "流总数：10" in prompt and "告警数：2" in prompt
    assert "第19轮" in prompt
    assert "第0轮" not in prompt  # 只带最近 12 轮
    assert prompt.rstrip().endswith("现在多少条？")


def test_assistant_snapshot_is_zeros_on_empty_database(tmp_path):
    """快照必须是可照抄的数字，不能因为库里没数据就整段消失。"""
    from center.main import dashboard_snapshot
    from center.rules import RuleEngine

    lines = dashboard_snapshot(Store(str(tmp_path / "empty.db")), RuleEngine(), 0.0)
    text = "\n".join(lines)
    assert "流总数：0" in text
    assert "告警数：0" in text
