"""HybridForest 的结构性自测（合成数据，不依赖 CIC-IDS2017）。"""

import numpy as np
import pytest
from sklearn.datasets import make_classification

from models.hybrid_forest import HybridForest, count_trees


def make_data(n=1500, n_classes=6, n_features=20, seed=0):
    return make_classification(
        n_samples=n,
        n_features=n_features,
        n_informative=12,
        n_redundant=2,
        n_classes=n_classes,
        n_clusters_per_class=1,
        random_state=seed,
    )


@pytest.fixture(scope="module")
def small_forest():
    X, y = make_data()
    model = HybridForest(
        n_estimators=6, base_rounds=10, base_depth=3, max_features="sqrt", random_state=0
    ).fit(X, y)
    return model, X, y


def test_proba_is_full_width_and_normalised(small_forest):
    model, X, _ = small_forest
    proba = model.predict_proba(X)
    assert proba.shape == (len(X), len(model.classes_))
    assert np.allclose(proba.sum(axis=1), 1.0)
    # 每个成员都可能没抽到某些类，一定要散射回全宽，否则列会静默错位
    assert proba.min() >= 0.0


def test_predict_returns_known_classes(small_forest):
    model, X, _ = small_forest
    pred = model.predict(X)
    assert set(pred).issubset(set(model.classes_))


def test_all_three_boosters_actually_used(small_forest):
    model, _, _ = small_forest
    assert set(model.learner_kinds_) <= {"xgboost", "lightgbm", "catboost"}
    assert set(model.estimator_counts_) == {"xgboost", "lightgbm", "catboost"}


def test_tree_count_counts_trees_not_rounds(small_forest):
    model, _, _ = small_forest
    k = len(model.classes_)
    expected = sum(
        10 if kind == "catboost" else 10 * k
        for kind in model.learner_kinds_
    )
    assert count_trees(model) == expected
    # 报"轮数"会把 XGB/LGBM 那两路低估 6 倍
    assert count_trees(model) > 6 * 10


def test_catboost_multiclass_builds_one_tree_per_round():
    """CatBoost MultiClass 是多维叶子，轮数即树数；XGB/LGBM 则是每轮每类一棵。
    这条口径差异直接决定成本表，必须钉住。"""
    X, y = make_data(n=1200)
    model = HybridForest(
        n_estimators=2, base_rounds=10, base_depth=3, base_pool=("catboost",), random_state=0
    ).fit(X, y)
    assert count_trees(model) == 2 * 10

    model = HybridForest(
        n_estimators=2, base_rounds=10, base_depth=3, base_pool=("lightgbm",), random_state=0
    ).fit(X, y)
    assert count_trees(model) == 2 * 10 * len(model.classes_)


def test_feature_importance_has_full_width(small_forest):
    model, X, _ = small_forest
    imp = model.feature_importances_
    assert imp.shape == (X.shape[1],)
    assert (imp >= 0).all()


def test_deep_base_learner_is_rejected():
    X, y = make_data(n=300)
    with pytest.raises(ValueError, match="base_depth"):
        HybridForest(max_depth=6, base_depth=24, n_estimators=1, base_rounds=2).fit(X, y)


def test_dart_override_reaches_lightgbm():
    X, y = make_data(n=600)
    model = HybridForest(
        n_estimators=2,
        base_rounds=10,
        base_depth=3,
        base_pool=("lightgbm",),
        base_overrides={"lightgbm": {"boosting_type": "dart", "drop_rate": 0.1}},
        random_state=0,
    ).fit(X, y)
    assert model.estimators_[0].boosting_type == "dart"


def test_rare_class_missing_from_a_bootstrap_still_works():
    """构造一个极稀有类，逼某些 bootstrap 抽不到它，验证概率散射不出错。"""
    X, y = make_data(n=1200)
    y = y.astype(int)
    y[-3:] = y.max() + 1  # 追加 3 个样本的稀有类
    model = HybridForest(n_estimators=8, base_rounds=5, base_depth=3, random_state=0).fit(X, y)
    proba = model.predict_proba(X)
    assert proba.shape == (len(X), y.max() + 1)
    assert np.allclose(proba.sum(axis=1), 1.0)
