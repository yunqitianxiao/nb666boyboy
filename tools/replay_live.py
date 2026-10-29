"""把数据集里的会话按节奏经真实 HTTP 接口送进中心，用于现场演示。

答辩机上没有 CAP_NET_RAW，抓包这一环由本脚本替代：特征向量、鉴权、推理、告警、
报告全部走真实代码路径，唯一被替换的是"帧从哪里来"。

    python3 tools/replay_live.py                      # 每 2 秒 2 条，一直跑
    python3 tools/replay_live.py --once --limit 40    # 发 40 条就退出
    python3 tools/replay_live.py --dry-run            # 只在本地跑规则，不发请求

BENIGN 行先在本地过一遍 flow_rules()：数据集里约 48% 的正常行是单包短流，会命中
portscan_short（该规则在测试集上精确率只有 0.468），不筛的话一分钟能刷出二十几条误报，
每条还各触发一次大模型调用。
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

import httpx
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from center.rules import flow_rules  # noqa: E402
from probe.features import FEATURE_ORDER  # noqa: E402

# 每类的五元组模板：(协议, 源 IP 前缀, 目的 IP, 目的端口回退值)
TOPOLOGY = {
    "BENIGN": ("6", "10.1.1.", "10.0.0.200", 443),
    "PortScan": ("6", "10.9.9.", "10.0.0.200", None),
    "DDoS": ("6", "10.2.2.", "10.0.0.200", 80),
    "DoS Hulk": ("6", "10.3.3.", "10.0.0.200", 80),
    "Patator": ("6", "10.4.4.", "10.0.0.55", 22),
    "Heartbleed": ("6", "10.5.5.", "10.0.0.200", 443),
}
ATTACK_ORDER = ["PortScan", "DDoS", "DoS Hulk", "Patator", "Heartbleed"]


def load_pool(path: Path, per_class: int) -> dict[str, list[dict]]:
    cols = set(FEATURE_ORDER) | {"Label"}
    df = pd.read_csv(path, usecols=lambda c: c in cols, low_memory=False)
    df = df.replace([float("inf"), float("-inf")], pd.NA).dropna()
    label_col = next(c for c in df.columns if c.strip().lower() == "label")
    df["Label"] = df[label_col].astype(str).str.strip()

    pool: dict[str, list[dict]] = {}
    skipped = 0
    for cls, part in df.groupby("Label", sort=False):
        rows = part.head(per_class)
        if cls == "BENIGN":
            keep = []
            for rec in rows.to_dict("records"):
                feats = {k: float(rec[k]) for k in FEATURE_ORDER}
                if flow_rules(feats):
                    skipped += 1
                    continue
                keep.append(rec)
            rows = pd.DataFrame(keep)
        pool[str(cls)] = rows.to_dict("records")
    if skipped:
        print(f"[预筛] BENIGN 跳过 {skipped} 条会误触发单流规则的行")
    return {k: v for k, v in pool.items() if v}


def make_flow(rec: dict, cls: str, seq: int, now: float) -> dict:
    proto, ip_prefix, dst_ip, fallback_port = TOPOLOGY.get(cls, TOPOLOGY["BENIGN"])
    dport = int(rec.get("Destination Port", fallback_port) or fallback_port or 0)

    if cls == "PortScan":
        # 扫描的源固定、目的端口逐条递增，窗口规则才判得出"同源探了很多端口"
        src_ip = f"{ip_prefix}9"
        sport = 40000
    elif cls == "BENIGN":
        src_ip = f"{ip_prefix}{random.randint(1, 12)}"
        sport = random.randint(32768, 60999)
    else:
        src_ip = f"{ip_prefix}{random.randint(1, 30)}"
        sport = random.randint(32768, 60999)

    dur_s = float(rec.get("Flow Duration", 0.0) or 0.0) / 1e6
    return {
        "key": f"{proto}|{src_ip}|{sport}|{dst_ip}|{dport}",
        "first_seen": now - dur_s,
        "last_seen": now,
        "values": [float(rec[name]) for name in FEATURE_ORDER],
    }


def build_batch(pool, n, attack_every, seq, now):
    batch = []
    for _ in range(n):
        seq += 1
        is_attack = attack_every > 0 and seq % attack_every == 0
        if is_attack:
            candidates = [c for c in ATTACK_ORDER if c in pool]
            cls = candidates[(seq // attack_every) % len(candidates)] if candidates else "BENIGN"
        else:
            cls = "BENIGN"
        rows = pool.get(cls) or pool["BENIGN"]
        rec = rows[seq % len(rows)]
        batch.append(make_flow(rec, cls, seq, now))
    return batch, seq


def main() -> int:
    ap = argparse.ArgumentParser(description="按节奏把数据集会话回放进中心")
    ap.add_argument("--data", default="data/cicids2017_sample.csv")
    ap.add_argument("--center", default="http://127.0.0.1:8000")
    ap.add_argument("--token", default="change-me")
    ap.add_argument("--probe-id", default="probe-pc1")
    ap.add_argument("--per-class", type=int, default=600, help="每类从数据集取多少行做素材")
    ap.add_argument("--burst", type=int, default=2, help="每批发几条")
    ap.add_argument("--rate", type=float, default=2.0, help="每批间隔秒数")
    ap.add_argument("--attack-every", type=int, default=4,
                    help="每多少条流插一条攻击流；0 表示只发 BENIGN")
    ap.add_argument("--limit", type=int, default=0, help="最多发多少条，0 表示不限")
    ap.add_argument("--once", action="store_true", help="发完 --limit 就退出")
    ap.add_argument("--dry-run", action="store_true", help="只在本地跑规则，不发请求")
    args = ap.parse_args()

    pool = load_pool(ROOT / args.data, args.per_class)
    print(f"[素材] {', '.join(f'{k}:{len(v)}' for k, v in pool.items())}")

    url = args.center.rstrip("/") + "/api/v1/report"
    headers = {"X-Probe-Token": args.token}

    if args.dry_run:
        batch, _ = build_batch(pool, 20, args.attack_every, 0, time.time())
        for flow in batch:
            feats = dict(zip(FEATURE_ORDER, flow["values"]))
            hits = [h.rule for h in flow_rules(feats)]
            print(flow["key"], "规则命中" if hits else "无", hits)
        return 0

    seq = 0
    sent = 0
    alerts = 0
    with httpx.Client(timeout=30, trust_env=False) as client:
        while True:
            n = args.burst if not args.limit else min(args.burst, args.limit - sent)
            if n <= 0:
                break
            batch, seq = build_batch(pool, n, args.attack_every, seq, time.time())
            now = time.time()
            payload = {
                "probe_id": args.probe_id,
                "sent_at": now,
                "window": {"start": now - args.rate, "end": now},
                "feature_names": list(FEATURE_ORDER),
                "flows": batch,
            }
            try:
                resp = client.post(url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                print(f"[错误] 连不上中心 {url}：{exc}")
                return 1
            if resp.status_code != 200:
                print(f"[错误] {resp.status_code}：{resp.text[:200]}")
                return 1
            res = resp.json()
            sent += res.get("accepted", 0)
            alerts += res.get("alerts", 0)
            print(f"[{time.strftime('%H:%M:%S')}] 已发 {sent} 条，累计告警 {alerts} 条", flush=True)
            if args.limit and sent >= args.limit:
                break
            time.sleep(args.rate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
