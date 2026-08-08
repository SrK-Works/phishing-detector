"""Loads the trained artifact and turns a feature dict into a verdict with
a SHAP-based explanation -- the main upgrade over the old project's bare
-1/1 output.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import pandas as pd
import shap
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from app.config import settings

LEGIT_LABEL = 1

# A verdict computed from a probability this close to the 0.5 boundary is
# barely more informed than a coin flip -- worth flagging explicitly rather
# than presenting it with the same visual confidence as a 95% call.
LOW_CONFIDENCE_BAND = 0.15


@dataclass(frozen=True)
class Prediction:
    verdict: str  # "safe" | "phishing"
    confidence: float  # probability of the predicted verdict, 0-1
    legit_probability: float
    low_confidence: bool  # probability landed close to the 0.5 boundary
    top_reasons: list[tuple[str, float]]  # (feature_name, signed SHAP value), by |impact|


class PhishingModel:
    def __init__(self, artifact_path: Path | None = None):
        artifact_path = artifact_path or settings.model_artifact_path
        bundle = joblib.load(artifact_path)
        self.pipeline: Pipeline = bundle["pipeline"]
        self.feature_names: list[str] = bundle["feature_names"]
        self.background_sample: pd.DataFrame = bundle["background_sample"]
        self._legit_index = list(self.pipeline.classes_).index(LEGIT_LABEL)
        self._explainer = None

    def _row_from_features(self, flat_features: dict) -> pd.DataFrame:
        row = {name: flat_features.get(name) for name in self.feature_names}
        return pd.DataFrame([row], columns=self.feature_names)

    def _preprocessing_only(self) -> Pipeline:
        return Pipeline(self.pipeline.steps[:-1])

    def _get_explainer(self):
        """Picks an explicit SHAP explainer type by model class rather than
        shap.Explainer's auto-dispatch: that generic picker chose
        TreeExplainer for XGBoost here too, but XGBoost 3.x's default tree
        construction trips a "categorical split not yet supported" error
        inside shap's tree-mode fast path unless told to use path-dependent
        perturbation explicitly.
        """
        if self._explainer is None:
            clf = self.pipeline.named_steps["clf"]
            if isinstance(clf, LogisticRegression):
                background = self._preprocessing_only().transform(self.background_sample)
                self._explainer = shap.LinearExplainer(
                    clf, background, feature_names=self.feature_names
                )
            else:
                self._explainer = shap.TreeExplainer(
                    clf,
                    feature_perturbation="tree_path_dependent",
                    feature_names=self.feature_names,
                )
        return self._explainer

    def _explain(self, row: pd.DataFrame, top_n: int) -> list[tuple[str, float]]:
        try:
            transformed = self._preprocessing_only().transform(row)
            shap_values = self._get_explainer()(transformed)
            values = shap_values.values[0]
            # Some explainers return one value per class (n_features, n_classes)
            # rather than one per feature; keep the "legitimate" class column.
            if values.ndim > 1:
                values = values[:, self._legit_index]
            ranked = sorted(
                zip(self.feature_names, values), key=lambda kv: abs(kv[1]), reverse=True
            )
            return [(name, float(val)) for name, val in ranked[:top_n]]
        except Exception:
            return []

    def predict(self, flat_features: dict, top_n: int = 5) -> Prediction:
        row = self._row_from_features(flat_features)
        proba = self.pipeline.predict_proba(row)[0]
        legit_probability = float(proba[self._legit_index])
        verdict = "safe" if legit_probability >= 0.5 else "phishing"
        confidence = legit_probability if verdict == "safe" else 1.0 - legit_probability

        return Prediction(
            verdict=verdict,
            confidence=confidence,
            legit_probability=legit_probability,
            low_confidence=abs(legit_probability - 0.5) < LOW_CONFIDENCE_BAND,
            top_reasons=self._explain(row, top_n),
        )
