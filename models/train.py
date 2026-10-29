"""五模型对比训练与选型。

用法：:

    # 五模型主对比
    python -m models.train --data data/cicids2017_sample.csv
    # 只跑一两个模型，快速验证链路
    python -m models.train --data data/cicids2017_sample.csv --only xgboost hybrid_forest
    # DART 消融（残差相关，单列一节）
    python -m models.train --data data/cicids2017_sample.csv --dart-ablation

产物：
    models/artifacts/best_model.pkl       最优模型 + scaler + 特征口径（一个包，推理侧只用它）
    models/artifacts/feature_schema.json  特征列名/顺序、scaler 参数、类别表
    models/artifacts/comparison.json      五模型同口径指标明细

为什么选 macro-F1 而不是准确率：CIC-IDS2017 里 BENIGN 约占 80%，全判"正常"就有 80% 准确率。
macro-F1 对每一类同等加权，稀有类判错会直接掉分，才压得住这种退化。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

try:
    from .hybrid_forest import HybridForest, count_trees
    from .labels import LABEL_MAP, normalize_label
except ImportError:
    from hybrid_forest import HybridForest, count_trees
    from labels import LABEL_MAP, normalize_label

try:
    from settings import deep_merge, load_config  # noqa: F401  (deep_merge 供外部复用)
except ImportError:  # python models/train.py 时仓库根不在 sys.path 上
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from settings import deep_merge, load_config  # noqa: F401

RARE_CLASS_SUPPORT = 30  # 测试集里样本数少于这个数的类，单类指标不可信


# ---------------------------------------------------------------- 配置与数据


def find_label_column(df):
    for col in df.columns:
        if col.strip().lower() == "label":
            return col
    raise SystemExit(f"找不到 Label 列，现有列名前 5 个：{list(df.columns)[:5]}")


def load_dataset(path, quick=None, seed=42):
    """返回 X, y, 特征列名, meta。

    meta 是与 X/y 逐行对齐的元数据表（`__source__`、`__order__`），
    时间留出要靠它的 `__order__`。
    """
    df = pd.read_csv(path, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]
    label_col = find_label_column(df)

    df = df[df[label_col].notna()].copy()
    df["__label__"] = df[label_col].map(normalize_label).map(LABEL_MAP)
    dropped = df["__label__"].isna().sum()
    if dropped:
        lost = df.loc[df["__label__"].isna(), label_col].value_counts()
        print(f"[数据] 丢弃 {dropped} 行：不属于六类的标签 -> {lost.to_dict()}", flush=True)
        df = df[df["__label__"].notna()]

    # 双下划线开头的是元数据（__label__、以及抽样脚本写入的 __source__ / __order__），
    # 不能当特征喂进模型，否则时间/跨天划分会用来源文件本身当预测依据
    meta_cols = [c for c in df.columns if c.startswith("__")]
    features = df.drop(columns=[label_col] + meta_cols)
    features = features.apply(pd.to_numeric, errors="coerce")
    features = features.replace([np.inf, -np.inf], np.nan)

    keep = features.notna().all(axis=1).to_numpy()
    if (~keep).sum():
        print(f"[数据] 丢弃 {(~keep).sum()} 行：含缺失值或无穷值", flush=True)

    X = features.to_numpy(dtype=np.float32)[keep]
    y = df["__label__"].to_numpy()[keep]
    meta = df.loc[keep, meta_cols].reset_index(drop=True)

    before = len(X)
    # CIC-IDS2017 自带重复行；用首现下标回填目标，别拿排好序的数组去索引
    _, first_idx = np.unique(X, axis=0, return_index=True)
    if len(first_idx) < before:
        sel = np.sort(first_idx)
        X, y, meta = X[sel], y[sel], meta.iloc[sel].reset_index(drop=True)
        print(f"[数据] 去掉 {before - len(X)} 行重复", flush=True)

    if quick and quick < len(X):
        # 抽下标而不是抽数组，否则 meta 与 X 的对应关系会断
        _, _, idx_tr, _ = train_test_split(
            np.arange(len(X)), y, train_size=quick, stratify=y, random_state=seed
        )
        sel = np.sort(idx_tr)
        X, y, meta = X[sel], y[sel], meta.iloc[sel].reset_index(drop=True)
        print(f"[数据] --quick 抽样到 {len(X)} 行", flush=True)

    print(f"[数据] 最终 {X.shape[0]} 行 × {X.shape[1]} 维特征，类别分布：", flush=True)
    for name, cnt in pd.Series(y).value_counts().items():
        print(f"        {name:<12} {cnt}", flush=True)
    return X, y, list(features.columns), meta


def split_by_time(X, y, order, test_size, val_size):
    """按类内部的时间顺序留出：最早 70% 训练、接着 20% 验证、最后 10% 测试。

    为什么不能整段按时间切：每个攻击类只占一段连续时间窗（DoS Hulk 集中在 Wednesday 文件
    前半段，Heartbleed 全在 86% 处）。整段切会把 DoS Hulk 全放进训练侧、Heartbleed 全放进
    测试侧。按类切保证六类都在三侧，测试侧取的是每类最晚的实例。

    也不做跨天留出：每个攻击类只出现在一天的文件里，留出整天等于测试侧出现训练时从未见过的类。
    """
    cuts = {name: [] for name in ("train", "val", "test")}
    for cls in np.unique(y):
        idx = np.flatnonzero(y == cls)
        idx = idx[np.argsort(order[idx], kind="stable")]
        n = len(idx)
        n_test = int(round(n * test_size))
        n_val = int(round(n * val_size))
        n_train = n - n_test - n_val
        if n_train <= 0:
            raise SystemExit(
                f"类 {cls} 只有 {n} 行，按 {test_size}/{val_size} 切不出训练集；"
                f"请提高该类配额或调小划比例"
            )
        cuts["train"].append(idx[:n_train])
        cuts["val"].append(idx[n_train:n_train + n_val])
        cuts["test"].append(idx[n_train + n_val:])
    return tuple(np.sort(np.concatenate(cuts[k])) for k in ("train", "val", "test"))


def forward_folds(y, order, test_size, n_blocks=5, min_train_blocks=2):
    """前向滚动验证（expanding window）：每类按时间切块，逐块往后滚。

    为什么不只用一次性的 val：val 只占一段、且紧挨着训练段，模型在这段上的表现几乎
    等于训练表现，分辨不出"会不会在更晚的数据上退化"。实测随机森林与 XGBoost 在
    验证集上同为 0.9975，在最后 10% 上却差 0.024（0.9500 vs 0.9743）——用 val 选型
    等于抛硬币。把开发段切成多块往后滚，验证块离训练数据越来越远，退化才显形。

    末尾 test_size 那一段完全不参与，只在最终汇报时用一次。
    """
    blocks = {}
    for cls in np.unique(y):
        idx = np.flatnonzero(y == cls)
        idx = idx[np.argsort(order[idx], kind="stable")]
        n_dev = int(round(len(idx) * (1.0 - test_size)))
        blocks[cls] = np.array_split(idx[:n_dev], n_blocks)

    folds = []
    for k in range(min_train_blocks, n_blocks):
        tr, va = [], []
        for parts in blocks.values():
            tr.append(np.concatenate(parts[:k]))
            va.append(parts[k])
        folds.append((np.sort(np.concatenate(tr)), np.sort(np.concatenate(va))))
    return folds


def split_and_scale(X, y, test_size, val_size, seed, order=None):
    if order is None:
        X_tmp, X_test, y_tmp, y_test = train_test_split(
            X, y, test_size=test_size, stratify=y, random_state=seed
        )
        val_frac = val_size / (1.0 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_tmp, y_tmp, test_size=val_frac, stratify=y_tmp, random_state=seed
        )
    else:
        tr, va, te = split_by_time(X, y, order, test_size, val_size)
        X_train, X_val, X_test = X[tr], X[va], X[te]
        y_train, y_val, y_test = y[tr], y[va], y[te]
    scaler = StandardScaler().fit(X_train)  # 只在训练集上拟合，防止验证/测试信息泄漏
    # 前向滚动验证模式下没有单独的验证段，StandardScaler 不收 0 行的数组
    X_val = scaler.transform(X_val) if len(X_val) else X_val
    return (
        scaler.transform(X_train),
        X_val,
        scaler.transform(X_test),
        y_train,
        y_val,
        y_test,
        scaler,
    )


# ------------------------------------------------------------------ 模型构建


def build_model(name, mcfg, seed):
    if name == "decision_tree":
        return DecisionTreeClassifier(random_state=seed, **mcfg["decision_tree"])
    if name == "random_forest":
        return RandomForestClassifier(random_state=seed, **mcfg["random_forest"])
    if name == "xgboost":
        return XGBClassifier(random_state=seed, tree_method="hist", verbosity=0, **mcfg["xgboost"])
    if name == "logistic":
        return LogisticRegression(random_state=seed, **mcfg["logistic"])
    if name == "hybrid_forest":
        h = mcfg["hybrid_forest"]
        return HybridForest(
            n_estimators=h["n_estimators"],
            max_depth=h["max_depth"],
            max_features=h["max_features"],
            base_depth=h["base_depth"],
            base_rounds=h["base_rounds"],
            base_pool=tuple(h["base_pool"]),
            base_overrides=h.get("base_overrides"),
            class_weight=h.get("class_weight", "balanced"),
            random_state=seed,
            n_jobs=h.get("n_jobs", -1),
        )
    raise SystemExit(f"未知模型：{name}，可选 {mcfg['candidates']}")


def balanced_weights(y):
    """与 class_weight='balanced' 等价的样本权重，给不支持 class_weight 的 XGBoost 用。"""
    classes, counts = np.unique(y, return_counts=True)
    per = len(y) / (len(classes) * counts)
    table = dict(zip(classes, per))
    return np.array([table[v] for v in y], dtype=np.float64)


def fit_model(model, name, X_train, y_train):
    if name == "xgboost":
        return model.fit(X_train, y_train, sample_weight=balanced_weights(y_train))
    return model.fit(X_train, y_train)


# -------------------------------------------------------------------- 评估


def evaluate(model, X, y_enc, classes):
    """classes 是标签名列表；y_enc 是它们对应的 0..K-1 整数下标。"""
    t0 = time.perf_counter()
    y_pred = model.predict(X)
    predict_ms = (time.perf_counter() - t0) / max(len(y_enc), 1) * 1000.0

    labels = list(range(len(classes)))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_enc, y_pred, labels=labels, average=None, zero_division=0
    )
    # 稀有类的单类 F1 本质是噪声，但它和常见类一样占 macro-F1 的 1/K 权重。
    # Heartbleed 在全量数据里只有 11 行，测试集 1 行 —— 判对判错直接摆动 1/6 的总分，
    # 用它来选模型等于抛硬币（实测把随机森林从第一拉到第五）。所以选型用剔除稀有类后的口径。
    reliable = [i for i, s in enumerate(support) if s >= RARE_CLASS_SUPPORT]
    macro_reliable = float(np.mean(f1[reliable])) if reliable else float("nan")
    return {
        "accuracy": float(accuracy_score(y_enc, y_pred)),
        "macro_f1": float(f1_score(y_enc, y_pred, average="macro", zero_division=0)),
        "macro_f1_reliable": macro_reliable,
        "excluded_from_reliable": [str(classes[i]) for i in labels if i not in reliable],
        "weighted_f1": float(f1_score(y_enc, y_pred, average="weighted", zero_division=0)),
        "predict_ms_per_row": float(predict_ms),
        "per_class": {
            str(c): {
                "precision": float(precision[i]),
                "recall": float(recall[i]),
                "f1": float(f1[i]),
                "support": int(support[i]),
            }
            for i, c in enumerate(classes)
        },
        "confusion_matrix": confusion_matrix(y_enc, y_pred, labels=labels).tolist(),
    }


def selection_score(metrics):
    """选型只看剔除稀有类后的 macro-F1；没有可信类时才退回原始 macro-F1。"""
    score = metrics["macro_f1_reliable"]
    return score if score == score else metrics["macro_f1"]  # NaN 判断


def saturation_note(results):
    """第一名和第二名分不出来时返回一句说明，否则返回 None。

    只看前两名的差值，不看全体极差：逻辑回归掉队会把极差撑大，
    让这个告警永远不触发（第一版就是这么写的，等于空转）。
    """
    ranking = sorted(((r["selection_score"], k) for k, r in results.items()), reverse=True)
    if len(ranking) < 2:
        return None
    gap = ranking[0][0] - ranking[1][0]
    if gap >= 0.005:
        return None
    return (
        f"{ranking[0][1]}（{ranking[0][0]:.4f}）与 {ranking[1][1]}（{ranking[1][0]:.4f}）"
        f"相差 {gap:.4f}，不到 0.005：这个数据集上它们已经饱和，名次不代表真实差距"
    )


def warn_rare_classes(metrics):
    for cls, row in metrics["per_class"].items():
        if row["support"] < RARE_CLASS_SUPPORT:
            print(
                f"[警告] {cls} 在测试集只有 {row['support']} 个样本，"
                f"该类的 P/R/F1 是噪声，报告里必须声明不可据此下结论",
                flush=True,
            )


# ------------------------------------------------------------------ 主流程


def main(argv=None):
    ap = argparse.ArgumentParser(description="NetSentinel-LLM 五模型对比训练")
    ap.add_argument("--data", required=True, help="CIC-IDS2017 抽样 CSV")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--out", default="models/artifacts")
    ap.add_argument("--quick", type=int, default=None, help="只取 N 行，快速验证链路")
    ap.add_argument("--only", nargs="*", default=None, help="只训练指定模型")
    ap.add_argument("--dart-ablation", action="store_true", help="只跑 DART 消融")
    ap.add_argument("--seed", type=int, default=None, help="覆盖 config 里的 random_state")
    ap.add_argument(
        "--split",
        choices=("random", "temporal", "temporal-cv"),
        default="random",
        help="random=分层随机划分（有泄漏，指标饱和）；temporal=按类内部时间顺序留出；"
        "temporal-cv=前向滚动验证选型 + 末尾留出汇报（报告用这个）",
    )
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    mcfg = cfg["model"]
    seed = args.seed if args.seed is not None else mcfg["random_state"]
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    X, y, feature_names, meta = load_dataset(args.data, quick=args.quick, seed=seed)
    # 统一编码一次：XGBoost 的 sklearn 接口只接受 0..K-1 的整数标签，字符串会直接报错。
    # 因此五个模型全部在整数标签上训练，predict() 返回的也是下标，靠 artifact 里的 classes 还原名称。
    encoder = LabelEncoder().fit(y)
    y_enc = encoder.transform(y)
    classes = [str(c) for c in encoder.classes_]

    order = None
    folds = None
    if args.split in ("temporal", "temporal-cv"):
        if "__order__" not in meta.columns:
            raise SystemExit(
                f"--split {args.split} 需要 __order__ 列（全局时间序号）。"
                "用 tools/build_sample.py 重新生成样本即可。"
            )
        order = meta["__order__"].to_numpy()
    if args.split == "temporal":
        print("[划分] 按类内部时间顺序留出：每类最早 70% 训练 / 接着 20% 验证 / 最后 10% 测试", flush=True)
    elif args.split == "temporal-cv":
        folds = forward_folds(y_enc, order, mcfg["test_size"])
        print(
            f"[划分] 前向滚动验证 {len(folds)} 折（开发段切块，训练块逐折递增），"
            f"末尾 {mcfg['test_size']:.0%} 留作测试集",
            flush=True,
        )

    # 滚动验证模式没有单独的 val 段（验证已经分摊到各折里）
    val_size = 0.0 if folds is not None else mcfg["val_size"]
    X_train, X_val, X_test, y_train, y_val, y_test, scaler = split_and_scale(
        X, y_enc, mcfg["test_size"], val_size, seed, order=order
    )
    print(
        f"[划分] train {len(X_train)} / val {len(X_val)} / test {len(X_test)}，"
        f"共 {len(classes)} 类",
        flush=True,
    )

    if args.dart_ablation:
        run_dart_ablation(cfg, X_train, y_train, X_test, y_test, classes, seed, out_dir)
        return 0

    targets = args.only or mcfg["candidates"]
    cv_scores = {}
    if folds is not None:
        print("[滚动] 前向滚动验证（选择分 = 各折可信 macro-F1 的均值）", flush=True)
        for name in targets:
            scores = []
            for tr, va in folds:
                fold_scaler = StandardScaler().fit(X[tr])
                fold_model = build_model(name, mcfg, seed)
                fit_model(fold_model, name, fold_scaler.transform(X[tr]), y_enc[tr])
                fold_metrics = evaluate(fold_model, fold_scaler.transform(X[va]), y_enc[va], classes)
                scores.append(selection_score(fold_metrics))
            cv_scores[name] = (float(np.mean(scores)), float(np.std(scores)), scores)
            print(
                f"[滚动] {name:<15} 各折 " + " ".join(f"{s:.4f}" for s in scores)
                + f"  均值 {np.mean(scores):.4f} ± {np.std(scores):.4f}",
                flush=True,
            )

    results = {}
    fitted = {}
    for name in targets:
        model = build_model(name, mcfg, seed)
        t0 = time.perf_counter()
        fit_model(model, name, X_train, y_train)
        fit_s = time.perf_counter() - t0

        # 滚动模式没有单独验证段；其余两种模式正常评一次
        val_metrics = evaluate(model, X_val, y_val, classes) if len(X_val) else None
        test_metrics = evaluate(model, X_test, y_test, classes)
        trees = count_trees(model)
        if val_metrics is not None:
            score = selection_score(val_metrics)
        else:
            score = cv_scores[name][0]
        results[name] = {
            "fit_seconds": round(fit_s, 2),
            "tree_count": trees,
            "val": val_metrics,
            "test": test_metrics,
            "selection_score": score,
            "cv_folds": cv_scores[name][2] if name in cv_scores else None,
        }
        fitted[name] = model
        head = f"[训练] {name:<15} {fit_s:6.1f}s  树 {trees:<7} "
        if val_metrics is not None:
            head += (
                f"val 可信macro-F1 {selection_score(val_metrics):.4f}  "
                f"(含稀有类 {val_metrics['macro_f1']:.4f})  "
            )
        else:
            head += f"滚动均值 {score:.4f}  "
        print(head + f"test 可信macro-F1 {test_metrics['macro_f1_reliable']:.4f}", flush=True)
        warn_rare_classes(test_metrics)

    best_name = max(results, key=lambda k: results[k]["selection_score"])
    best_model = fitted[best_name]
    excluded = sorted(
        {c for r in results.values() if r["val"] for c in r["val"]["excluded_from_reliable"]}
    )
    basis = "滚动验证均值" if folds is not None else "验证集可信 macro-F1"
    print(
        f"\n[选型] {best_name} 胜出（{basis}="
        f"{results[best_name]['selection_score']:.4f}）；测试集指标仅作最终汇报，不参与选择",
        flush=True,
    )
    if excluded:
        print(
            f"[选型] 这些类测试/验证样本不足 {RARE_CLASS_SUPPORT} 个，未计入可信 macro-F1：{excluded}",
            flush=True,
        )
    # 真正的饱和信号是"第一名和第二名分不开"，不是全体极差
    note = saturation_note(results)
    if note:
        print(f"[选型] 注意：{note}", flush=True)

    artifact = {
        "model": best_model,
        "scaler": scaler,
        "feature_names": feature_names,
        "classes": classes,
        # 推理侧约定：model.predict() 返回的是这里的下标，必须过 classes[pred] 才是类名
        "predict_returns": "class_index",
        "label_map": LABEL_MAP,
        "selected_by": (
            f"forward-chaining cv mean macro_f1_reliable (剔除样本数 < {RARE_CLASS_SUPPORT} 的类)"
            if folds is not None
            else f"val macro_f1_reliable (剔除样本数 < {RARE_CLASS_SUPPORT} 的类)"
        ),
        "metrics": results[best_name],
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    joblib.dump(artifact, out_dir / "best_model.pkl")

    schema = {
        "feature_names": feature_names,
        "classes": classes,
        "predict_returns": "class_index",
        "label_map": LABEL_MAP,
        "scaler": {
            "mean": scaler.mean_.tolist(),
            "scale": scaler.scale_.tolist(),
            "var": scaler.var_.tolist(),
        },
        "n_features": len(feature_names),
    }
    (out_dir / "feature_schema.json").write_text(
        json.dumps(schema, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out_dir / "comparison.json").write_text(
        json.dumps(
            {"best": best_name, "models": results, "split": {
                "mode": args.split,
                "train": int(len(X_train)), "val": int(len(X_val)), "test": int(len(X_test)),
                "cv_folds": None if folds is None else [
                    {"train": int(len(tr)), "val": int(len(va))} for tr, va in folds
                ],
            }},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("\n| 模型 | 树数 | 训练(s) | test 可信macro-F1 | test macro-F1(含稀有类) | test 加权F1 | 准确率 |")
    print("|---|---|---|---|---|---|---|")
    for name, row in results.items():
        tm = row["test"]
        print(
            f"| {name} | {row['tree_count']} | {row['fit_seconds']} | "
            f"{tm['macro_f1_reliable']:.4f} | {tm['macro_f1']:.4f} | "
            f"{tm['weighted_f1']:.4f} | {tm['accuracy']:.4f} |"
        )
    print(f"\n产物已写入 {out_dir}/")
    return 0


def run_dart_ablation(cfg, X_train, y_train, X_test, y_test, classes, seed, out_dir):
    """DART 消融：固定 LightGBM 为唯一基学习器，只改 boosting_type 一处变量。

    CatBoost 没有 DART 实现，不能当消融载体；把消融塞进混合森林会同时改变
    "库种类"和"丢弃策略"两个变量，结论不可归因。
    """
    mcfg = cfg["model"]
    acfg = mcfg["dart_ablation"]
    if not acfg.get("enabled", True):
        print("[DART] config 里 dart_ablation.enabled=false，跳过", flush=True)
        return

    rows = {}
    for variant in acfg["variants"]:
        name = variant["name"]
        overrides = {k: v for k, v in variant.items() if k != "name"}
        model = HybridForest(
            n_estimators=acfg["n_estimators"],
            max_depth=mcfg["hybrid_forest"]["max_depth"],
            max_features=acfg["max_features"],
            base_depth=acfg["base_depth"],
            base_rounds=acfg["base_rounds"],
            base_pool=("lightgbm",),
            base_overrides={"lightgbm": overrides},
            random_state=seed,
            n_jobs=mcfg["hybrid_forest"].get("n_jobs", -1),
        )
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        fit_s = time.perf_counter() - t0
        metrics = evaluate(model, X_test, y_test, classes)
        rows[name] = {
            "params": overrides,
            "fit_seconds": round(fit_s, 2),
            "tree_count": count_trees(model),
            "test": metrics,
        }
        print(
            f"[DART] {name:<12} {fit_s:6.1f}s  test macro-F1 {metrics['macro_f1']:.4f}",
            flush=True,
        )

    # 基线固定取 config 里排第一的变体，别用 dict 顺序——变体顺序一调，相对增量会静默换基准
    base_name = acfg["variants"][0]["name"]
    base = rows[base_name]["test"]["macro_f1"]
    print(f"\n基线 = {base_name}（config 里 dart_ablation.variants 的第一项）")
    print("| 变体 | 配置 | 训练(s) | test macro-F1 | 相对基线 |")
    print("|---|---|---|---|---|")
    for name, row in rows.items():
        delta = row["test"]["macro_f1"] - base
        print(
            f"| {name} | {row['params']} | {row['fit_seconds']} | "
            f"{row['test']['macro_f1']:.4f} | {delta:+.4f} |"
        )
    (out_dir / "dart_ablation.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("\n注意：收益很小甚至为负都是正常结论，报告里如实写，不要当创新点包装。")


if __name__ == "__main__":
    sys.exit(main())
