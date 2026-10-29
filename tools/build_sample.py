"""从 CIC-IDS2017 官方 8 个 MachineLearningCVE CSV 抽出一份可训练的小样本。

为什么要按类配额抽，而不是按比例抽：
全量 2,830,743 行里 BENIGN 占 80.3%，Heartbleed 只有 11 行。如果按同一个比例抽到 25 万行
（约 8.8%），Heartbleed 只会剩 1 行，7:2:1 划分后测试集 0 行——这个类等于被抹掉了。
所以按"每类配额"抽：常见类截断，稀有类全收。代价是训练集的类别先验被抬高，
报告里必须写明这一点，不能拿这个样本上的准确率当线上准确率。

用法::

    python3 tools/build_sample.py
    python3 tools/build_sample.py --quota BENIGN=80000,"DoS Hulk"=30000 --out /tmp/small.csv
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

# 直接跑脚本时 sys.path[0] 是 tools/，仓库根不在路径上，手动补上才能共用标签映射
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from models.labels import CLASSES, LABEL_MAP, normalize_label  # noqa: E402

# 目标总量约 25 万；稀有类自然全收
DEFAULT_QUOTA = {
    "BENIGN": 120_000,
    "DoS Hulk": 40_000,
    "PortScan": 40_000,
    "DDoS": 40_000,
    "Patator": 13_835,
    "Heartbleed": 11,
}


def label_column(df):
    for col in df.columns:
        if col.strip().lower() == "label":
            return col
    raise SystemExit(f"找不到 Label 列：{list(df.columns)[-3:]}")


def count_by_file(files):
    """第一遍只读 Label 列，拿到 (文件, 类) 的行数，用来给每个文件分配合适的配额。"""
    counts = {}
    for path in files:
        df = pd.read_csv(path, usecols=lambda c: c.strip().lower() == "label", low_memory=False)
        mapped = df.iloc[:, 0].map(normalize_label).map(LABEL_MAP)
        counts[path] = Counter(mapped.dropna().tolist())
        print(f"[扫描] {path.name}: {dict(counts[path])}", flush=True)
    return counts


def allocate(counts, quota, classes):
    """把每类配额按"该类在各文件中的占比"分摊下去，用最大余数法保证分完不剩。"""
    per_class_total = Counter()
    for file_counts in counts.values():
        per_class_total.update(file_counts)

    alloc = {path: Counter() for path in counts}
    for cls in classes:
        total = per_class_total[cls]
        target = min(quota[cls], total)
        if total == 0:
            continue
        raw = {p: target * counts[p][cls] / total for p in counts}
        floors = {p: int(np.floor(v)) for p, v in raw.items()}
        remain = target - sum(floors.values())
        order = sorted(raw, key=lambda p: raw[p] - floors[p], reverse=True)
        for p in order[:remain]:
            floors[p] += 1
        for p, n in floors.items():
            if n:
                alloc[p][cls] = n
    return alloc, per_class_total


def build(files, alloc, seed):
    rng = np.random.RandomState(seed)
    chunks = []
    # __order__ 是全局时间序号：按"天 -> 文件内行号"递增。文件名字母序不等于时间序
    # （Friday 排在 Monday 前面），所以必须显式给出时间顺序，否则按时间留出会切错。
    cursor = 0
    for path in files:
        if not alloc[path]:
            continue
        df = pd.read_csv(path, low_memory=False)
        df.columns = [str(c).strip() for c in df.columns]
        col = label_column(df)
        canon = df[col].map(normalize_label).map(LABEL_MAP)

        picked = []
        for cls, n in alloc[path].items():
            idx = np.flatnonzero((canon == cls).to_numpy())
            if n >= len(idx):
                picked.append(idx)
            else:
                picked.append(rng.choice(idx, size=n, replace=False))
        idx = np.sort(np.concatenate(picked))
        sub = df.iloc[idx].copy()
        sub[col] = canon.iloc[idx]
        # 保留来源文件与全局时间序号，供按时间留出的评估使用
        # （随机划分会把同一天的近似重复流同时分到训练和测试，指标被抬到 0.999，
        #   这正是 CIC-IDS2017 被诟病的地方）
        sub["__source__"] = path.name
        sub["__order__"] = cursor + idx
        cursor += len(df)
        chunks.append(sub)
        print(f"[抽取] {path.name}: {len(sub)} 行", flush=True)

    out = pd.concat(chunks, ignore_index=True)
    out = out.sample(frac=1.0, random_state=seed).reset_index(drop=True)  # 打散行顺序
    return out


def chronological_order():
    """按时间先后排列的文件名关键字。文件名的字母序不等于时间序。"""
    return [
        "Monday-WorkingHours",
        "Tuesday-WorkingHours",
        "Wednesday-workingHours",
        "Thursday-WorkingHours-Morning-WebAttacks",
        "Thursday-WorkingHours-Afternoon-Infilteration",
        "Friday-WorkingHours-Morning",
        "Friday-WorkingHours-Afternoon-DDos",
        "Friday-WorkingHours-Afternoon-PortScan",
    ]


def parse_quota(text):
    if not text:
        return dict(DEFAULT_QUOTA)
    quota = dict(DEFAULT_QUOTA)
    for item in text.split(","):
        name, _, val = item.partition("=")
        quota[name.strip()] = int(val)
    return quota


def main(argv=None):
    ap = argparse.ArgumentParser(description="抽取 CIC-IDS2017 六类小样本")
    ap.add_argument("--raw-dir", default="data/raw/cicids2017")
    ap.add_argument("--out", default="data/cicids2017_sample.csv")
    ap.add_argument("--quota", default=None, help='形如 "BENIGN=80000,DoS Hulk=30000"')
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)

    raw_dir = Path(args.raw_dir)
    day_order = chronological_order()
    # 按时间顺序排列，而不是文件名字母序：字母序 Friday 会排在 Monday 前面
    files = sorted(
        raw_dir.glob("*.csv"),
        key=lambda p: next(
            (i for i, k in enumerate(day_order) if p.stem.startswith(k)), len(day_order)
        ),
    )
    if len(files) != 8:
        raise SystemExit(f"{raw_dir} 下应有 8 个 CSV（官方 MachineLearningCVE），实际 {len(files)} 个")
    names = [p.stem for p in files]
    if len(set(names)) != 8:
        raise SystemExit(f"文件与时间顺序表未一一对应：{names}")

    quota = parse_quota(args.quota)
    classes = list(CLASSES)

    counts = count_by_file(files)
    alloc, totals = allocate(counts, quota, classes)

    out = build(files, alloc, args.seed)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(out_path, index=False)

    label_col = label_column(out)
    final = out[label_col].value_counts().to_dict()
    print(f"\n[写出] {out_path}  {len(out):,} 行 × {out.shape[1]} 列 "
          f"({out_path.stat().st_size / 1e6:.0f} MB)", flush=True)
    for cls in classes:
        n = final.get(cls, 0)
        print(f"    {cls:<12} {n:>7,}  (全量 {totals[cls]:>9,})", flush=True)

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_dir": str(raw_dir),
        "source_files": [p.name for p in files],
        "seed": args.seed,
        "rows": int(len(out)),
        "columns": int(out.shape[1]),
        "quota": quota,
        "class_counts": {c: int(final.get(c, 0)) for c in classes},
        "source_class_totals": {c: int(totals[c]) for c in classes},
        "sampling": "per-class quota (stratified across files), not proportional",
        "source_column": "__source__",
        "order_column": "__order__",
        "known_issues": [
            "全量 2,830,743 行中 Heartbleed 仅 11 行，按比例抽样会把它抹掉，故稀有类全收；"
            "训练集类别先验因此高于真实分布，本样本上的准确率不能当作线上准确率。",
            "Kaggle 上的这三个 Web Attack 标签里的 en dash 已被写坏成 U+FFFD（2180 处），"
            "它们不属于六类，抽取时已被丢弃。",
            "列名已去掉首尾空格（原文件形如 ' Destination Port'）。",
            "__source__ 列记录了每行来自哪个原始 CSV，训练时不作特征（双下划线开头一律剔除），"
            "用于按天/按文件划分的跨天评估。",
            "__order__ 列是全局时间序号，按'天 -> 文件内行号'递增（文件名字母序不等于时间序），"
            "用于按时间留出。注意每个攻击类只占一段连续时间窗：DoS Hulk 集中在 Wednesday 文件前"
            "半段（分位 0.13/0.28/0.46）、Heartbleed 全在 0.86 处，所以整段按时间切会让 DoS Hulk"
            "全部落进训练侧、Heartbleed 全部落进测试侧。跨天留出同理不可行——每个攻击类只出现在"
            "一天的文件里。可行的口径是按类内部时间顺序留出（见 models/train.py --split temporal）。",
        ],
    }
    mpath = out_path.with_name(out_path.stem + "_manifest.json")
    mpath.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[清单] {mpath}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
