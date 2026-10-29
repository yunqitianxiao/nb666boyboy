"""M11 离线基线：单流规则在时间留出集上的表现，用来和小模型同口径对照。

    python tools/rules_baseline.py --data data/cicids2017_sample.csv

只有**单流规则**能在这里评。CSV 里没有时间戳、没有源/目的 IP——端口扫描要的"同一源在
窗口内探了多少个目的端口"一行都没有，暴力破解同理。所以这份结果测的是规则的弱化形态，
不是线上规则引擎的全部能力。报告里必须这么写，否则会拿一个必然很差的数字去替规则层下结论。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from center.rules import flow_rules, pick  # noqa: E402
from models.train import RARE_CLASS_SUPPORT, load_dataset, split_by_time  # noqa: E402


def baseline_predictions(X, feature_names) -> list[str]:
    """逐行跑单流规则，没命中就是 BENIGN。"""
    out = []
    for row in X:
        feats = dict(zip(feature_names, (float(v) for v in row)))
        hit = pick(flow_rules(feats))
        out.append(hit.category if hit else "BENIGN")
    return out


def score(y_true, y_pred, classes) -> dict:
    per_class = {}
    for cls in classes:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p == cls)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != cls and p == cls)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == cls and p != cls)
        support = sum(1 for t in y_true if t == cls)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[cls] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": support,
            "reliable": support >= RARE_CLASS_SUPPORT,
        }
    reliable = [m for m in per_class.values() if m["reliable"]]
    macro = sum(m["f1"] for m in reliable) / len(reliable) if reliable else 0.0
    acc = sum(1 for t, p in zip(y_true, y_pred) if t == p) / len(y_true)
    return {
        "accuracy": round(acc, 4),
        "macro_f1_reliable": round(macro, 4),
        "per_class": per_class,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="M11 单流规则基线（与小模型同口径）")
    parser.add_argument("--data", required=True)
    parser.add_argument("--test-size", type=float, default=0.10)
    parser.add_argument("--val-size", type=float, default=0.20)
    parser.add_argument("--out", default=str(ROOT / "models" / "artifacts" / "rules_baseline.json"))
    args = parser.parse_args(argv)

    X, y, feature_names, meta = load_dataset(args.data)
    if "__order__" not in meta.columns:
        raise SystemExit("需要 __order__ 列才能按与小模型相同的口径留出测试集")
    order = meta["__order__"].to_numpy()

    _, _, test_idx = split_by_time(X, y, order, args.test_size, args.val_size)
    X_test, y_test = X[test_idx], y[test_idx]
    classes = sorted(set(y_test))

    print(f"[基线] 测试集 {len(X_test)} 行（与小模型同一段留出）", flush=True)
    preds = baseline_predictions(X_test, feature_names)
    result = score(list(y_test), preds, classes)

    print(f"{'类别':<12}{'精确率':>8}{'召回率':>8}{'F1':>8}{'样本数':>8}")
    for cls in classes:
        m = result["per_class"][cls]
        flag = "" if m["reliable"] else "  (样本太少，不评估)"
        print(f"{cls:<12}{m['precision']:>8.3f}{m['recall']:>8.3f}{m['f1']:>8.3f}"
              f"{m['support']:>8}{flag}")
    print(f"\n准确率 {result['accuracy']:.4f}　"
          f"macro-F1（剔除样本 < {RARE_CLASS_SUPPORT} 的类）{result['macro_f1_reliable']:.4f}")

    missed = {cls: sum(1 for t, p in zip(y_test, preds) if t == cls and p == "BENIGN")
              for cls in classes}
    print("完全漏报（判成 BENIGN）的行数：", missed)

    result["split"] = {"mode": "temporal", "test_size": args.test_size, "val_size": args.val_size}
    result["rows"] = len(X_test)
    result["missed_as_benign"] = missed
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[基线] 写入 {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
