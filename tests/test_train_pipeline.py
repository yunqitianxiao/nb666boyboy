"""训练管线的数据侧自测：标签归并、去重、缺失/无穷值剔除。

不去不碰真实数据集，全部用合成 CSV，保证 CI 上不依赖 1.2 GB 的 CIC-IDS2017。
"""

import numpy as np
import pandas as pd
import pytest

from models.train import LABEL_MAP, load_dataset, main, normalize_label

N_FEATURES = 12


def make_csv(path, n_per_class=40, classes=None, seed=0):
    classes = classes or ["BENIGN", "PortScan", "DDoS", "DoS Hulk", "FTP-Patator", "Heartbleed"]
    rng = np.random.RandomState(seed)
    rows = []
    for i, cls in enumerate(classes):
        block = rng.normal(loc=i, scale=1.0, size=(n_per_class, N_FEATURES)).astype("float32")
        frame = pd.DataFrame(block, columns=[f"feat_{j}" for j in range(N_FEATURES)])
        frame["Label"] = cls
        rows.append(frame)
    pd.concat(rows, ignore_index=True).to_csv(path, index=False)
    return path


def test_normalize_label_handles_dash_variants():
    # CIC-IDS2017 的 Web Attack 用的是 en dash，Patator 用的是普通短横，必须统一
    assert normalize_label("Web Attack – Brute Force") == "web attack - brute force"
    assert normalize_label("  FTP-Patator ") == "ftp-patator"
    assert normalize_label("DoS   Hulk") == "dos hulk"


def test_patator_variants_collapse_to_one_class():
    assert LABEL_MAP["ftp-patator"] == "Patator"
    assert LABEL_MAP["ssh-patator"] == "Patator"


def test_label_map_is_idempotent():
    """回归：抽样后的 CSV 里存的已经是规范名，训练时再映射一遍必须还是规范名。

    映射不幂等时，Patator（规范名）会被当成"不属于六类"整类丢掉，
    而且日志里只有一行"丢弃 13835 行"，训练照常跑完，指标看起来完全正常。
    """
    from models.labels import CLASSES

    for canonical in CLASSES:
        assert LABEL_MAP.get(normalize_label(canonical)) == canonical


def test_canonical_label_csv_keeps_all_six_classes(tmp_path):
    path = make_csv(
        tmp_path / "canonical.csv",
        n_per_class=10,
        classes=["BENIGN", "DDoS", "DoS Hulk", "Heartbleed", "Patator", "PortScan"],
    )
    X, y, _, _ = load_dataset(path)
    assert set(y) == {"BENIGN", "DDoS", "DoS Hulk", "Heartbleed", "Patator", "PortScan"}
    assert X.shape[0] == 6 * 10


def test_load_dataset_maps_labels_and_reports(tmp_path):
    path = make_csv(tmp_path / "sample.csv")
    X, y, names, _ = load_dataset(path)
    assert set(y) == {"BENIGN", "PortScan", "DDoS", "DoS Hulk", "Patator", "Heartbleed"}
    assert names == [f"feat_{j}" for j in range(N_FEATURES)]
    assert X.shape == (6 * 40, N_FEATURES)


def test_duplicate_rows_are_dropped_and_labels_stay_aligned(tmp_path):
    """回归：去重时如果拿 np.unique 排好序的数组去索引目标，标签会整体错位。"""
    path = make_csv(tmp_path / "sample.csv", n_per_class=10)
    df = pd.read_csv(path)
    dup = df.iloc[[0]].copy()
    dup["feat_0"] = 999.0  # 造一行"独一无二"的，便于定位
    dup["Label"] = "PortScan"
    pd.concat([df, dup, dup], ignore_index=True).to_csv(path, index=False)

    X, y, _, _ = load_dataset(path)
    assert X.shape[0] == 6 * 10 + 1  # 重复的两行被合并成一行
    assert set(y) == {"BENIGN", "PortScan", "DDoS", "DoS Hulk", "Patator", "Heartbleed"}


def test_unknown_labels_are_dropped(tmp_path):
    path = make_csv(tmp_path / "sample.csv", n_per_class=10)
    df = pd.read_csv(path)
    extra = df.iloc[[0]].copy()
    extra["feat_0"] = -777.0
    extra["Label"] = "Bot"
    pd.concat([df, extra], ignore_index=True).to_csv(path, index=False)

    X, y, _, _ = load_dataset(path)
    assert X.shape[0] == 6 * 10
    assert "Bot" not in set(y)


def test_inf_and_nan_rows_are_dropped(tmp_path):
    path = make_csv(tmp_path / "sample.csv", n_per_class=10)
    df = pd.read_csv(path)
    df.loc[0, "feat_1"] = np.inf
    df.loc[1, "feat_2"] = np.nan
    df.to_csv(path, index=False)

    X, y, _, _ = load_dataset(path)
    assert X.shape[0] == 6 * 10 - 2


def test_metadata_columns_are_not_used_as_features(tmp_path):
    """回归：抽样脚本写的 __source__ 若被当成特征，跨天划分就等于把答案喂给模型。"""
    path = make_csv(tmp_path / "with_meta.csv", n_per_class=10)
    df = pd.read_csv(path)
    df["__source__"] = "Monday-WorkingHours.pcap_ISCX.csv"
    df.to_csv(path, index=False)

    X, y, names, _ = load_dataset(path)
    assert "__source__" not in names
    assert names == [f"feat_{j}" for j in range(N_FEATURES)]
    assert X.shape == (6 * 10, N_FEATURES)


def test_saturation_note_fires_when_top_two_are_tied():
    """回归：告警只看前两名差值。第一版用全体极差判断，逻辑回归掉队把极差撑大，
    告警永远不触发 —— 判据空转比没有判据更糟。"""
    from models.train import saturation_note

    tied = {
        "xgboost": {"selection_score": 0.9992},
        "decision_tree": {"selection_score": 0.9991},
        "logistic": {"selection_score": 0.9557},  # 掉队者不该影响判断
    }
    assert saturation_note(tied) is not None

    separated = {
        "xgboost": {"selection_score": 0.9992},
        "decision_tree": {"selection_score": 0.9500},
    }
    assert saturation_note(separated) is None
    assert saturation_note({"only_one": {"selection_score": 0.99}}) is None


def test_split_by_time_accepts_zero_val():
    """回归：前向滚动验证模式传 val_size=0，StandardScaler 不收 0 行数组会直接抛。"""
    from models.train import split_and_scale

    rng = np.random.RandomState(0)
    X = rng.normal(size=(200, 3)).astype("float32")
    y = np.repeat([0, 1], 100)
    order = np.arange(200, dtype=float)

    X_train, X_val, X_test, *_ = split_and_scale(
        X, y, test_size=0.1, val_size=0.0, seed=0, order=order
    )
    assert X_val.shape == (0, 3)
    assert len(X_train) == 180 and len(X_test) == 20


def test_forward_folds_never_touch_the_test_segment():
    """回归：滚动验证一旦把最后 10% 漏进某一折，选型就提前看到了测试集，
    后面的"留出汇报"整段失效，而且日志完全正常。"""
    from models.train import forward_folds

    rng = np.random.RandomState(0)
    classes = ["BENIGN", "DDoS", "PortScan", "DoS Hulk"]
    y = np.repeat(classes, 100)
    order = rng.permutation(len(y))  # 每类内部的时间序号故意和行号无关

    test_size = 0.1
    folds = forward_folds(y, order, test_size, n_blocks=5, min_train_blocks=2)
    assert len(folds) == 3

    # 每类最晚的 10% 是测试段，任何一折都不许碰
    test_rows = set()
    for cls in classes:
        idx = np.flatnonzero(y == cls)
        idx = idx[np.argsort(order[idx], kind="stable")]
        test_rows.update(idx[int(round(len(idx) * (1 - test_size))):].tolist())

    for tr, va in folds:
        assert not (set(tr.tolist()) & set(va.tolist()))
        assert not (set(tr.tolist()) & test_rows)
        assert not (set(va.tolist()) & test_rows)

    # 各折的验证块互不重叠，且训练块逐折变长
    val_sets = [set(va.tolist()) for _, va in folds]
    assert sum(len(s) for s in val_sets) == len(set().union(*val_sets))
    assert [len(tr) for tr, _ in folds] == sorted(len(tr) for tr, _ in folds)


def test_end_to_end_writes_artifacts(tmp_path):
    data = make_csv(tmp_path / "sample.csv", n_per_class=80)
    out = tmp_path / "artifacts"
    code = main(
        [
            "--data", str(data),
            "--out", str(out),
            "--only", "decision_tree", "hybrid_forest",
        ]
    )
    assert code == 0
    assert (out / "best_model.pkl").exists()
    assert (out / "feature_schema.json").exists()
    assert (out / "comparison.json").exists()

    # 推理侧契约：predict() 返回的是 classes 的下标，不是类名
    import joblib

    artifact = joblib.load(out / "best_model.pkl")
    assert artifact["predict_returns"] == "class_index"
    X, _, names, _ = load_dataset(data)
    assert artifact["feature_names"] == names
    Xs = artifact["scaler"].transform(X)
    pred = artifact["model"].predict(Xs)
    assert set(pred).issubset(set(range(len(artifact["classes"]))))
    assert set(np.asarray(artifact["classes"])[pred]) == set(
        ["BENIGN", "PortScan", "DDoS", "DoS Hulk", "Patator", "Heartbleed"]
    )
