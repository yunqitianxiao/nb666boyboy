"""跨天留出的补充证据：训练日（周一至周四）→ 测试日（周五）。

为什么单独做这个实验：按类内部时间留出（models/train.py --split temporal）测的是
"同一个类更晚的实例还能不能认出来"，仍然是闭集问题。CIC-IDS2017 更真实的失效模式是
**测试日出现训练时从未见过的攻击类型**——周五有 DDoS 和 PortScan，而周一至周四完全没有。
六类闭集模型遇到这种行的行为只有两种：认成某个已知类，或者认成 BENIGN。

这里跑两个实验：

  A. 闭集六类模型（只在周一至周四能见到的四类上训练）直接拿去测周五：
     看 DDoS / PortScan 的行有多少被"至少报了警"（预测 != BENIGN），
     以及 BENIGN 行有多少被误报。这是开集检测能力的上界/下界的实测。
  B. 二分类（BENIGN vs 攻击）在同样的跨天条件下训练和测试：
     看"只判断有没有攻击"这个更弱的问题，跨天后退化到什么程度。

结论无论正负都照实写。这个实验的目的不是证明模型好，是给报告里
"为什么在线路径需要大模型层兜底"提供实测依据。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support
from xgboost import XGBClassifier

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from models.train import balanced_weights, load_dataset  # noqa: E402

TRAIN_DAYS = ("Monday", "Tuesday", "Wednesday", "Thursday")
TEST_DAY = "Friday"


def day_of(source: str) -> str:
    """把 '__source__'（如 Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv）映到星期。"""
    return source.split("-", 1)[0]


def fit_xgb(X, y, seed):
    n_classes = len(np.unique(y))
    model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="binary:logistic" if n_classes == 2 else "multi:softprob",
        tree_method="hist",
        verbosity=0,
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X, y, sample_weight=balanced_weights(y))
    return model


def per_class_rows(y_true, y_pred, names):
    labels = list(range(len(names)))
    p, r, f, s = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average=None, zero_division=0
    )
    return {
        names[i]: {
            "precision": round(float(p[i]), 4),
            "recall": round(float(r[i]), 4),
            "f1": round(float(f[i]), 4),
            "support": int(s[i]),
        }
        for i in labels
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="跨天留出评估（周一至周四训练，周五测试）")
    ap.add_argument("--data", default="data/cicids2017_sample.csv")
    ap.add_argument("--out", default="models/artifacts/cross_day.json")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args(argv)

    X, y, feature_names, meta = load_dataset(args.data)
    if "__source__" not in meta.columns:
        raise SystemExit("样本缺 __source__ 列，用 tools/build_sample.py 重新生成")

    days = meta["__source__"].map(day_of).to_numpy()
    is_train = np.isin(days, TRAIN_DAYS)
    is_test = days == TEST_DAY
    print(
        f"[切分] 训练日 {sorted(set(days[is_train]))} {is_train.sum()} 行 / "
        f"测试日 {TEST_DAY} {is_test.sum()} 行",
        flush=True,
    )

    for side, mask in (("训练侧", is_train), ("测试侧", is_test)):
        dist = pd.Series(y[mask]).value_counts()
        print(f"  {side}类别：" + "，".join(f"{k} {v}" for k, v in dist.items()), flush=True)

    # 标准化只在训练日上拟合，测试日自己是完全没见过的
    mean = X[is_train].mean(axis=0)
    std = X[is_train].std(axis=0)
    std[std == 0] = 1.0
    Xs = (X - mean) / std

    out = {"train_days": list(TRAIN_DAYS), "test_day": TEST_DAY}

    # ---------------------------------------------------------------- 实验 A
    # 闭集：训练侧只有 BENIGN / DoS Hulk / Patator / Heartbleed 四类
    a_classes = sorted(set(y[is_train]))
    a_map = {c: i for i, c in enumerate(a_classes)}
    y_a_tr = np.array([a_map[v] for v in y[is_train]])
    model_a = fit_xgb(Xs[is_train], y_a_tr, args.seed)

    pred_a = model_a.predict(Xs[is_test])
    benign_idx = a_map["BENIGN"]
    alerted = pred_a != benign_idx

    friday = pd.DataFrame({"label": y[is_test], "alerted": alerted, "pred": pred_a})
    exp_a = {}
    for cls, grp in friday.groupby("label"):
        exp_a[str(cls)] = {
            "rows": int(len(grp)),
            "alert_rate": round(float(grp["alerted"].mean()), 4),
            "predicted_as": {
                a_classes[i]: int(n)
                for i, n in grp["pred"].value_counts().sort_index().items()
            },
        }
    print("\n[实验 A] 闭集四类模型直接测周五（模型不知道 DDoS / PortScan 这两类存在）", flush=True)
    print(f"{'周五真实类':<12}{'行数':>8}{'报警率':>10}  预测去向", flush=True)
    for cls, row in exp_a.items():
        top = sorted(row["predicted_as"].items(), key=lambda kv: -kv[1])[:3]
        print(
            f"{cls:<12}{row['rows']:>8}{row['alert_rate']:>10.2%}  "
            + "，".join(f"{k} {v}" for k, v in top),
            flush=True,
        )
    out["A_closed_set"] = {"trained_classes": a_classes, "per_class": exp_a}

    # ---------------------------------------------------------------- 实验 B
    # 二分类：BENIGN=0，其余=1。这个问题比六类弱，但仍然跨天
    y_b_tr = (y[is_train] != "BENIGN").astype(int)
    y_b_te = (y[is_test] != "BENIGN").astype(int)
    model_b = fit_xgb(Xs[is_train], y_b_tr, args.seed)
    pred_b = model_b.predict(Xs[is_test])

    b_names = ["BENIGN", "ATTACK"]
    exp_b = per_class_rows(y_b_te, pred_b, b_names)
    acc_b = float((pred_b == y_b_te).mean())
    # 按周五的攻击类型拆开看召回：二分类模型对 DDoS 和 PortScan 未必一样
    detail = {}
    for cls in sorted(set(y[is_test])):
        m = y[is_test] == cls
        detail[str(cls)] = {
            "rows": int(m.sum()),
            "attack_recall": round(float(pred_b[m].mean()), 4),
        }
    print("\n[实验 B] 二分类（BENIGN vs 攻击）同样跨天", flush=True)
    print(f"  准确率 {acc_b:.4f}", flush=True)
    for name, row in exp_b.items():
        print(f"  {name:<8} P {row['precision']:.4f}  R {row['recall']:.4f}  F1 {row['f1']:.4f}"
              f"  样本 {row['support']}", flush=True)
    out["B_binary"] = {"accuracy": round(acc_b, 4), "per_class": exp_b, "by_friday_class": detail}

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n产物已写入 {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
