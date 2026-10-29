"""M6 中心端存储：SQLite 建表与读写。

四张表对应数据流的四个阶段：
  flows    每条流的小模型判定结果（原始特征也留着，诊断要拿它当证据）
  alerts   非 BENIGN 的流升级成的告警
  reports  针对告警生成的 LLM 诊断报告

看板助手的对话不落库：它不绑定任何一条告警，历史由看板会话带着走。
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

# 流水表里要展示的特征列。整份 78 维塞给看板会让 200 行响应到 1 MB 以上。
FLOW_DISPLAY_FIELDS = (
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "SYN Flag Count",
    "RST Flag Count",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id    TEXT    NOT NULL,
    first_seen  REAL    NOT NULL,
    last_seen   REAL    NOT NULL,
    flow_key    TEXT    NOT NULL,
    predicted   TEXT    NOT NULL,
    confidence  REAL    NOT NULL,
    features    TEXT    NOT NULL,
    created_at  REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_time ON flows(created_at);
CREATE INDEX IF NOT EXISTS idx_flows_probe ON flows(probe_id);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id    TEXT    NOT NULL,
    flow_key    TEXT    NOT NULL,
    category    TEXT    NOT NULL,
    confidence  REAL    NOT NULL,
    risk        TEXT    NOT NULL,
    features    TEXT    NOT NULL,
    evidence    TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'open',
    source      TEXT    NOT NULL DEFAULT 'model',
    rule        TEXT,
    proba       TEXT,
    created_at  REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    INTEGER NOT NULL,
    content     TEXT    NOT NULL,
    model       TEXT    NOT NULL,
    elapsed_ms  INTEGER NOT NULL DEFAULT 0,
    created_at  REAL    NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);
"""


class Store:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)

    @staticmethod
    def _migrate(conn) -> None:
        """给老库补列。CREATE TABLE IF NOT EXISTS 不会给已存在的表加列，
        少了这一步，老库上 source/rule/proba 会在读取时变成 KeyError。"""
        have = {r["name"] for r in conn.execute("PRAGMA table_info(alerts)")}
        added = []
        for col, ddl in (("source", "TEXT NOT NULL DEFAULT 'model'"), ("rule", "TEXT"),
                         ("proba", "TEXT")):
            if col not in have:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {ddl}")
                added.append(col)
        if "proba" in added:
            # 老库里 features 列实际存的是模型给出的各类概率，搬进新列；
            # 现在 features 恢复本义（78 维原始特征），报告侧读 proba
            conn.execute("UPDATE alerts SET proba = features")

    # ---------------------------------------------------------------- 写入

    def add_flow(self, probe_id, first_seen, last_seen, flow_key, predicted,
                 confidence, features) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO flows (probe_id, first_seen, last_seen, flow_key, predicted,"
                " confidence, features, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (probe_id, first_seen, last_seen, flow_key, predicted, confidence,
                 json.dumps(features, ensure_ascii=False), time.time()),
            )
            return int(cur.lastrowid)

    def add_alert(self, probe_id, flow_key, category, confidence, risk,
                  features, evidence, source="model", rule=None, proba=None) -> int:
        """source='model' 时 confidence 是分类概率；source='rule' 时是"超出阈值多少倍"，
        两者不能放在一起比。features 存 78 维原始特征，proba 存各类概率。"""
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO alerts (probe_id, flow_key, category, confidence, risk,"
                " features, evidence, source, rule, proba, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (probe_id, flow_key, category, confidence, risk,
                 json.dumps(features, ensure_ascii=False),
                 json.dumps(evidence, ensure_ascii=False), source, rule,
                 json.dumps(proba, ensure_ascii=False) if proba is not None else None,
                 time.time()),
            )
            return int(cur.lastrowid)

    def add_report(self, alert_id, content, model, elapsed_ms=0) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO reports (alert_id, content, model, elapsed_ms, created_at)"
                " VALUES (?,?,?,?,?)",
                (alert_id, content, model, elapsed_ms, time.time()),
            )
            return int(cur.lastrowid)

    # ---------------------------------------------------------------- 读取

    def alerts(self, limit=100, probe_id=None, category=None, since=None) -> list:
        sql = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if probe_id:
            sql += " AND probe_id=?"
            params.append(probe_id)
        if category:
            sql += " AND category=?"
            params.append(category)
        if since:
            sql += " AND created_at>=?"
            params.append(since)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            return [_row_to_dict(r) for r in conn.execute(sql, params)]

    def flows(self, limit=200, probe_id=None, since=None) -> list:
        """流水表用的轻量查询：78 维特征只留几列展示字段，别整包塞给看板。"""
        sql = "SELECT * FROM flows WHERE 1=1"
        params = []
        if probe_id:
            sql += " AND probe_id=?"
            params.append(probe_id)
        if since:
            sql += " AND created_at>=?"
            params.append(since)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        out = []
        with self.connect() as conn:
            for row in conn.execute(sql, params):
                d = _row_to_dict(row)
                feats = d.pop("features", {})
                d["summary"] = {k: feats[k] for k in FLOW_DISPLAY_FIELDS if k in feats}
                out.append(d)
        return out

    def alert(self, alert_id) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            return _row_to_dict(row) if row else None

    def report_for_alert(self, alert_id) -> dict | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM reports WHERE alert_id=? ORDER BY id DESC LIMIT 1", (alert_id,)
            ).fetchone()
            return _row_to_dict(row) if row else None

    def report(self, report_id) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
            return _row_to_dict(row) if row else None

    def stats(self, since=None) -> dict:
        since = since or (time.time() - 3600)
        with self.connect() as conn:
            total_flows = conn.execute(
                "SELECT COUNT(*) FROM flows WHERE created_at>=?", (since,)
            ).fetchone()[0]
            by_pred = {
                r["predicted"]: r["n"]
                for r in conn.execute(
                    "SELECT predicted, COUNT(*) AS n FROM flows WHERE created_at>=?"
                    " GROUP BY predicted", (since,)
                )
            }
            by_probe = {
                r["probe_id"]: r["n"]
                for r in conn.execute(
                    "SELECT probe_id, COUNT(*) AS n FROM flows WHERE created_at>=?"
                    " GROUP BY probe_id", (since,)
                )
            }
            # flow_key 形如 "6|10.0.0.1|50000|10.0.0.2|80"，第一段是 IP 协议号
            by_proto = {
                r["proto"]: r["n"]
                for r in conn.execute(
                    "SELECT substr(flow_key, 1, instr(flow_key, '|') - 1) AS proto,"
                    " COUNT(*) AS n FROM flows WHERE created_at>=? GROUP BY proto", (since,)
                )
            }
            alerts = [
                _row_to_dict(r)
                for r in conn.execute(
                    "SELECT id, category, probe_id, risk, confidence, created_at FROM alerts"
                    " WHERE created_at>=? ORDER BY id DESC LIMIT 200", (since,)
                )
            ]
            # 时序按 10 s 分桶，看板直接画折线，不用在前端再算
            buckets = [
                {"bucket": r["b"], "n": r["n"]}
                for r in conn.execute(
                    "SELECT CAST(created_at/10 AS INTEGER) AS b, COUNT(*) AS n FROM flows"
                    " WHERE created_at>=? GROUP BY b ORDER BY b", (since,)
                )
            ]
        return {
            "since": since,
            "total_flows": total_flows,
            "by_prediction": by_pred,
            "by_probe": by_probe,
            "by_protocol": by_proto,
            "alerts": alerts,
            "timeline": buckets,
        }


def _row_to_dict(row) -> dict:
    d = dict(row)
    for k in ("features", "evidence", "proba"):
        if k in d and isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except json.JSONDecodeError:
                pass
    return d
