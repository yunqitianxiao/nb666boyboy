"""M3 在线推理：把一批流特征变成「类别 + 置信度 + 风险等级」。

线上只加载一个 best_model.pkl。五个模型是离线对比实验（M8）的产物，
不是五个一起推理——上表里其余四个只存在于 comparison.json。

推理契约（由 models/train.py 写入 artifact）：
  model.predict() 返回的是 classes 的下标，不是类名；
  predict_proba() 的列序是 model.classes_，可能少于全量类别（某个基学习器没见过稀有类）。
两条都要在这里兑现，否则会把"决策树"的类别名跟"混合森林"的概率列串到一起，而且不会报错。
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np

# 类别先验风险：Heartbleed 是信息泄露，顶格；扫描类危害低但必须看得到
BASE_RISK = {
    "BENIGN": "info",
    "PortScan": "medium",
    "Patator": "high",
    "DDoS": "high",
    "DoS Hulk": "high",
    "Heartbleed": "critical",
}
RISK_ORDER = ["info", "low", "medium", "high", "critical"]


def escalate(risk: str, confidence: float) -> str:
    """置信度足够高时把风险抬一档；置信度低时如实降一档，别装作很确定。"""
    i = RISK_ORDER.index(risk)
    if confidence >= 0.99:
        i = min(i + 1, len(RISK_ORDER) - 1)
    elif confidence < 0.60:
        i = max(i - 1, 0)
    return RISK_ORDER[i]


class Detector:
    def __init__(self, model_path: str, schema_path: str | None = None):
        path = Path(model_path)
        if not path.exists():
            raise SystemExit(f"找不到模型产物 {path}，先跑 models/train.py")
        artifact = joblib.load(path)
        self.model = artifact["model"]
        self.scaler = artifact["scaler"]
        self.feature_names = list(artifact["feature_names"])
        self.classes = [str(c) for c in artifact["classes"]]
        if artifact.get("predict_returns") != "class_index":
            raise SystemExit(
                f"{path} 的 predict_returns={artifact.get('predict_returns')!r}，"
                "推理侧只支持 class_index 契约，请用当前版 models/train.py 重新训练"
            )
        self.label_map = artifact.get("label_map", {})
        self.trained_at = artifact.get("trained_at")
        self.selected_by = artifact.get("selected_by")
        self.artifact_metrics = artifact.get("metrics", {})

        if schema_path and Path(schema_path).exists():
            schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
            if schema.get("feature_names") != self.feature_names:
                raise SystemExit(
                    "feature_schema.json 与模型产物里的列序不一致 —— "
                    "重新训练或重新生成 schema，别让线上用错位的特征"
                )

    # ------------------------------------------------------------------ 校验

    def check_features(self, names) -> None:
        """探针报上来的列序必须和训练时一模一样。这里不是"宽容一点"的地方。"""
        names = list(names)
        if names == self.feature_names:
            return
        missing = [n for n in self.feature_names if n not in names]
        extra = [n for n in names if n not in self.feature_names]
        raise ValueError(
            f"特征列不符：缺 {missing[:5]}（共{len(missing)}）多 {extra[:5]}（共{len(extra)}）"
        )

    # ------------------------------------------------------------------ 推理

    def predict_batch(self, values) -> list[dict]:
        X = np.asarray(values, dtype=np.float64)
        if X.ndim != 2:
            X = X.reshape(1, -1)
        if X.shape[1] != len(self.feature_names):
            raise ValueError(f"期望 {len(self.feature_names)} 列，收到 {X.shape[1]} 列")

        Xs = self.scaler.transform(X)
        idx = np.asarray(self.model.predict(Xs)).astype(int)

        proba = self.model.predict_proba(Xs)
        # predict_proba 的列对外层类别下标：按 model.classes_ 映射回全量宽度，
        # 不能假设列序就是 0..K-1（某个基学习器漏掉稀有类时列会少）
        model_classes = np.asarray(getattr(self.model, "classes_", np.arange(len(self.classes))))
        proba_full = np.zeros((len(X), len(self.classes)), dtype=np.float64)
        for j, c in enumerate(model_classes):
            proba_full[:, int(c)] = proba[:, j]

        out = []
        for i in range(len(X)):
            name = self.classes[int(idx[i])]
            conf = float(proba_full[i, int(idx[i])])
            out.append(
                {
                    "category": name,
                    "confidence": round(conf, 6),
                    "risk": escalate(BASE_RISK.get(name, "medium"), conf),
                    "proba": {
                        cls: round(float(proba_full[i, k]), 6)
                        for k, cls in enumerate(self.classes)
                    },
                }
            )
        return out

    def top_features(self, values, k=5) -> list[dict]:
        """给诊断报告用的"证据链"：该流在哪几维特征上最偏离训练分布。

        用标准化后的绝对值排序，是启发式而不是归因——
        tree 模型的强项是分裂点，不是逐特征贡献。报告里必须这样措辞。
        """
        X = np.asarray(values, dtype=np.float64).reshape(1, -1)
        z = np.abs((X[0] - self.scaler.mean_) / np.where(self.scaler.scale_ == 0, 1, self.scaler.scale_))
        order = np.argsort(-z)[:k]
        return [
            {
                "feature": self.feature_names[i],
                "value": float(X[0, i]),
                "z_score": round(float(z[i]), 3),
            }
            for i in order
        ]
