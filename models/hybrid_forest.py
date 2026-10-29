"""混合森林：外层随机森林的 Bagging 骨架，内层基学习器是随机抽取的提升模型。

和随机森林的唯一区别：每个基学习器不再是一棵 CART，而是从 base_pool 里随机抽到的
XGBoost / LightGBM / CatBoost 之一，训练成一个小型提升模型（浅树 + 少轮数），
最后用软投票聚合各类概率。

三个必须守住的约束（写进报告 4.x）：
  1. 提升器内部必须是浅树（base_depth 默认 6）。24 层的树几乎能拟合完训练集，
     后续提升轮次没有残差可学，等于退化成"换个库跑单棵 CART"。
  2. base_depth 不得超过 max_depth（对应随机森林那 24 层的护栏），越界直接报错，
     不要静默截断。
  3. 树数口径按库分开算，不能一把尺子量三个库：
     XGBoost / LightGBM 多分类每轮**每类各长一棵树**（树数 = base_rounds * n_classes）；
     CatBoost MultiClass 每轮只长**一棵树**，叶子是 n_classes 维向量（树数 = base_rounds）。
     报成本必须报到树数，按"轮数"报会让 XGB/LGBM 那两路被低估 n_classes 倍。
"""

from __future__ import annotations

import math

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.validation import check_is_fitted

__all__ = ["HybridForest", "count_trees"]


def _build_booster(kind, rounds, depth, overrides, seed, n_jobs):
    overrides = dict(overrides or {})
    if kind == "xgboost":
        from xgboost import XGBClassifier

        kw = dict(
            n_estimators=rounds,
            max_depth=depth,
            learning_rate=0.1,
            subsample=0.9,
            colsample_bytree=1.0,
            tree_method="hist",
            n_jobs=n_jobs,
            random_state=seed,
            verbosity=0,
        )
        kw.update(overrides)
        return XGBClassifier(**kw)

    if kind == "lightgbm":
        from lightgbm import LGBMClassifier

        kw = dict(
            n_estimators=rounds,
            max_depth=depth,
            # LightGBM 是 leaf-wise 生长，只设 max_depth 挡不住叶子数，必须同时压 num_leaves
            num_leaves=2**depth - 1,
            learning_rate=0.1,
            subsample=0.9,
            subsample_freq=1,
            colsample_bytree=1.0,
            n_jobs=n_jobs,
            random_state=seed,
            verbose=-1,
        )
        kw.update(overrides)
        return LGBMClassifier(**kw)

    if kind == "catboost":
        from catboost import CatBoostClassifier

        kw = dict(
            iterations=rounds,
            depth=depth,
            learning_rate=0.1,
            rsm=1.0,
            thread_count=n_jobs,
            random_seed=seed,
            verbose=0,
            allow_writing_files=False,
        )
        kw.update(overrides)
        return CatBoostClassifier(**kw)

    raise ValueError(f"不支持的基学习器类型：{kind!r}，可选 xgboost / lightgbm / catboost")


class HybridForest(ClassifierMixin, BaseEstimator):
    """Bagging 骨架 + 随机抽取的提升器基学习器 + 软投票。

    Parameters
    ----------
    n_estimators : int
        基学习器个数。每个都是一个完整的提升模型，不是一个棵。
    max_depth : int
        Bagging 骨架的深度护栏（对应随机森林的 24 层）。基学习器内部深度不得超过它。
    max_features : {"sqrt", "log2", "auto"} / int / float / None
        每个基学习器看到的随机特征子集大小，语义与随机森林一致。
    base_depth : int
        提升器内部单棵浅树的深度，建议 3–8。
    base_rounds : int
        提升轮数。多分类下每轮每类各长一棵树。
    base_pool : sequence of str
        基学习器候选库，每个基学习器从中随机抽取一个。
    base_overrides : dict[str, dict]
        按库名注入额外参数，例如 {"lightgbm": {"boosting_type": "dart", "drop_rate": 0.1}}。
        这是 DART 消融实验的接入点。
    class_weight : {"balanced"} / dict / None
        类别权重。BENIGN 占 80%，不处理会让模型退化成"全判正常"。
    random_state : int / None
    n_jobs : int
        每个基学习器内部使用的线程数。基学习器之间是串行训练的，避免嵌套并行。
    """

    def __init__(
        self,
        n_estimators=24,
        max_depth=24,
        max_features="sqrt",
        base_depth=6,
        base_rounds=100,
        base_pool=("xgboost", "lightgbm", "catboost"),
        base_overrides=None,
        class_weight="balanced",
        random_state=None,
        n_jobs=-1,
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.max_features = max_features
        self.base_depth = base_depth
        self.base_rounds = base_rounds
        self.base_pool = base_pool
        self.base_overrides = base_overrides
        self.class_weight = class_weight
        self.random_state = random_state
        self.n_jobs = n_jobs

    # ---------------------------------------------------------------- 内部工具

    @staticmethod
    def _validate_X(X):
        if hasattr(X, "to_numpy"):
            return X.to_numpy(dtype=np.float32)
        return np.asarray(X, dtype=np.float32)

    def _resolve_max_features(self, n_features):
        mf = self.max_features
        if mf is None:
            return n_features
        if isinstance(mf, str):
            if mf in ("sqrt", "auto"):
                return max(1, int(math.sqrt(n_features)))
            if mf == "log2":
                return max(1, int(math.log2(n_features)))
            raise ValueError(f"不支持的 max_features：{mf!r}")
        if isinstance(mf, float):
            return max(1, min(n_features, int(mf * n_features)))
        return max(1, min(n_features, int(mf)))

    def _draw_kinds(self, rng):
        """随机分配基学习器种类，但保证各库数量均衡。

        纯独立随机在 n_estimators=24 时会有不小的概率某个库一次都抽不到，
        那这一路的知识就白丢了；先按轮次铺满再打乱，随机性和覆盖性都保住。
        """
        pool = list(self.base_pool)
        if not pool:
            raise ValueError("base_pool 不能为空")
        reps = int(math.ceil(self.n_estimators / len(pool)))
        kinds = pool * reps
        order = rng.permutation(len(kinds))
        return [kinds[i] for i in order[: self.n_estimators]]

    def _sample_weight(self, y_enc):
        cw = self.class_weight
        if cw is None:
            return None
        counts = np.bincount(y_enc, minlength=int(y_enc.max()) + 1).astype(np.float64)
        if cw == "balanced":
            per_class = len(y_enc) / (counts.size * np.maximum(counts, 1))
            return per_class[y_enc]
        if isinstance(cw, dict):
            return np.array([cw[c] for c in y_enc], dtype=np.float64)
        raise ValueError(f"不支持的 class_weight：{cw!r}")

    # ------------------------------------------------------------------- 训练

    def fit(self, X, y):
        if self.base_depth > self.max_depth:
            raise ValueError(
                f"base_depth={self.base_depth} 超过 max_depth={self.max_depth}："
                "提升器内部必须是浅树，深树会让提升轮次没有残差可学"
            )

        X = self._validate_X(X)
        y = np.asarray(y)
        self.n_features_in_ = X.shape[1]

        self._le = LabelEncoder().fit(y)
        y_enc = self._le.transform(y).astype(np.int32)
        self.classes_ = self._le.classes_
        n_classes = len(self.classes_)
        n_samples, n_features = X.shape

        rng = np.random.RandomState(self.random_state)
        n_sub = self._resolve_max_features(n_features)
        kinds = self._draw_kinds(rng)
        weights = self._sample_weight(y_enc)

        self.estimators_ = []
        self.feature_indices_ = []
        self.member_classes_ = []
        self.learner_kinds_ = []
        self.skipped_ = []

        for i, kind in enumerate(kinds):
            seed = int(rng.randint(0, 2**31 - 1))
            boot = rng.randint(0, n_samples, size=n_samples)
            feats = np.sort(rng.choice(n_features, size=n_sub, replace=False))
            y_sub = y_enc[boot]

            member_le = LabelEncoder().fit(y_sub)
            if len(member_le.classes_) < 2:
                self.skipped_.append((i, kind, "bootstrap 样本只有单一类别"))
                continue

            est = _build_booster(
                kind,
                rounds=self.base_rounds,
                depth=self.base_depth,
                overrides=(self.base_overrides or {}).get(kind),
                seed=seed,
                n_jobs=self.n_jobs,
            )
            fit_kwargs = {}
            if weights is not None:
                fit_kwargs["sample_weight"] = weights[boot]
            est.fit(X[np.ix_(boot, feats)], member_le.transform(y_sub), **fit_kwargs)

            self.estimators_.append(est)
            self.feature_indices_.append(feats)
            # 单个 bootstrap 可能没抽到稀有类，记下这个成员实际覆盖了哪几类，
            # 预测时把概率散射回全宽，否则列数对不上会静默错位
            self.member_classes_.append(member_le.classes_)
            self.learner_kinds_.append(kind)

        if not self.estimators_:
            raise RuntimeError("没有基学习器训练成功，检查 base_pool / 数据类别分布")

        self.estimator_counts_ = {
            k: self.learner_kinds_.count(k) for k in dict.fromkeys(self.learner_kinds_)
        }
        return self

    # ------------------------------------------------------------------- 预测

    def predict_proba(self, X):
        check_is_fitted(self, "estimators_")
        X = self._validate_X(X)
        proba = np.zeros((X.shape[0], len(self.classes_)), dtype=np.float64)
        for est, feats, classes_idx in zip(
            self.estimators_, self.feature_indices_, self.member_classes_
        ):
            proba[:, classes_idx] += est.predict_proba(X[:, feats])
        return proba / len(self.estimators_)

    def predict(self, X):
        proba = self.predict_proba(X)
        return self.classes_[np.argmax(proba, axis=1)]

    # --------------------------------------------------------------- 可解释性

    @property
    def feature_importances_(self):
        check_is_fitted(self, "estimators_")
        total = np.zeros(self.n_features_in_, dtype=np.float64)
        hits = np.zeros(self.n_features_in_, dtype=np.float64)
        for est, feats in zip(self.estimators_, self.feature_indices_):
            imp = getattr(est, "feature_importances_", None)
            if imp is None:
                continue
            total[feats] += np.asarray(imp, dtype=np.float64)
            hits[feats] += 1.0
        denom = np.maximum(hits, 1.0)
        return total / denom


def count_trees(model):
    """实际建成的树数，用于报告里的成本表。

    不能按"轮数"报：XGBoost / LightGBM 多分类每轮每类各长一棵树，差 n_classes 倍；
    CatBoost MultiClass 每轮只长一棵树（叶子是多维向量），轮数即树数。
    """
    if isinstance(model, HybridForest):
        return sum(count_trees(e) for e in getattr(model, "estimators_", []))
    if hasattr(model, "estimators_") and isinstance(model.estimators_, (list, np.ndarray)):
        return int(sum(count_trees(e) for e in model.estimators_))
    if hasattr(model, "get_booster"):  # xgboost
        return int(len(model.get_booster().get_dump()))
    if hasattr(model, "booster_"):  # lightgbm
        return int(model.booster_.num_trees())
    if hasattr(model, "tree_count_"):  # catboost
        return int(model.tree_count_)
    if hasattr(model, "tree_"):  # 单棵 CART
        return 1
    return 0
