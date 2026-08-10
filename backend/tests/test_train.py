import pandas as pd
from sklearn.linear_model import LogisticRegression

from app.model.train import evaluate, to_numeric_frame


def test_to_numeric_frame_drops_non_feature_columns():
    df = pd.DataFrame({
        "url": ["https://a.com", "https://b.com"],
        "label": [1, 0],
        "lexical_uses_https": [True, False],
    })
    numeric = to_numeric_frame(df)
    assert "url" not in numeric.columns
    assert "label" not in numeric.columns


def test_to_numeric_frame_converts_bools_to_floats():
    df = pd.DataFrame({"lexical_uses_https": [True, False]})
    numeric = to_numeric_frame(df)
    assert numeric["lexical_uses_https"].tolist() == [1.0, 0.0]


def test_to_numeric_frame_coerces_missing_to_nan():
    df = pd.DataFrame({"host_domain_age_days": [100, None]})
    numeric = to_numeric_frame(df)
    assert numeric["host_domain_age_days"].iloc[0] == 100.0
    assert pd.isna(numeric["host_domain_age_days"].iloc[1])


def test_evaluate_returns_expected_metric_keys():
    X = pd.DataFrame({"x": [0.0, 0.0, 1.0, 1.0, 0.1, 0.9, 0.2, 0.8]})
    y = pd.Series([0, 0, 1, 1, 0, 1, 0, 1])
    model = LogisticRegression().fit(X, y)
    metrics = evaluate(model, X, y)
    assert set(metrics) == {"accuracy", "precision", "recall", "f1", "roc_auc", "brier_score"}
    assert 0.0 <= metrics["brier_score"] <= 1.0
