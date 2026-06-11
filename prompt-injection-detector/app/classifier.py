"""ML classifier for prompt injection detection using scikit-learn."""

from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Literal

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.utils import class_weight

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "classifier.pkl"

DEFAULT_INJECTION_PROBABILITY = 0.1
INJECTION_THRESHOLD = 0.5

_loaded_pipeline: Pipeline | None = None
_model_warning: str | None = None


def _build_pipeline(class_weights: dict[int, float] | None = None) -> Pipeline:
    clf_kwargs: dict = {
        "max_iter": 1000,
        "C": 0.8,
        "solver": "lbfgs",
        "random_state": 42,
    }
    if class_weights is not None:
        clf_kwargs["class_weight"] = class_weights
    else:
        clf_kwargs["class_weight"] = "balanced"

    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 3),
                    min_df=2,
                    max_df=0.95,
                    sublinear_tf=True,
                    strip_accents="unicode",
                    analyzer="word",
                    token_pattern=r"\b[a-zA-Z][a-zA-Z0-9]*\b",
                    max_features=5000,
                ),
            ),
            ("clf", LogisticRegression(**clf_kwargs)),
        ]
    )


def _compute_class_weights(y: list[int]) -> dict[int, float]:
    classes = np.unique(y)
    weights = class_weight.compute_class_weight("balanced", classes=classes, y=y)
    return dict(zip(classes, weights))


def train(X: list[str], y: list[int], model_path: Path | None = None) -> Pipeline:
    """
    Train the classifier pipeline and save to disk.

    Args:
        X: Training text samples.
        y: Labels (0 = safe, 1 = injection).
        model_path: Optional override for output path.

    Returns:
        Fitted sklearn Pipeline.
    """
    destination = model_path or DEFAULT_MODEL_PATH
    destination.parent.mkdir(parents=True, exist_ok=True)

    class_weights = _compute_class_weights(y)
    pipeline = _build_pipeline(class_weights)
    pipeline.fit(X, y)

    with destination.open("wb") as f:
        pickle.dump(pipeline, f)

    logger.info("Classifier saved to %s", destination)
    return pipeline


def load_model(model_path: Path | None = None) -> bool:
    """
    Load the classifier pipeline into memory.

    Returns:
        True if model loaded successfully, False otherwise.
    """
    global _loaded_pipeline, _model_warning

    path = model_path or DEFAULT_MODEL_PATH

    if not path.exists():
        _loaded_pipeline = None
        _model_warning = f"No model found at {path}. Using default low-risk score."
        logger.warning(_model_warning)
        return False

    try:
        with path.open("rb") as f:
            _loaded_pipeline = pickle.load(f)
        _model_warning = None
        logger.info("Classifier loaded from %s", path)
        return True
    except Exception as exc:
        _loaded_pipeline = None
        _model_warning = f"Failed to load model: {exc}. Using default low-risk score."
        logger.error(_model_warning)
        return False


def get_model_warning() -> str | None:
    """Return the current model loading warning, if any."""
    return _model_warning


def predict(text: str) -> dict[str, float | Literal["safe", "injection"] | str | None]:
    """
    Predict injection probability for the given text.

    Returns:
        Dict with injection_probability, label, and optional warning.
    """
    if _loaded_pipeline is None:
        return {
            "injection_probability": DEFAULT_INJECTION_PROBABILITY,
            "label": "safe",
            "warning": _model_warning,
        }

    proba = _loaded_pipeline.predict_proba([text])[0]
    classes = list(_loaded_pipeline.classes_)
    injection_idx = classes.index(1) if 1 in classes else int(classes[-1])
    injection_probability = float(proba[injection_idx])
    label: Literal["safe", "injection"] = (
        "injection" if injection_probability >= INJECTION_THRESHOLD else "safe"
    )

    return {
        "injection_probability": injection_probability,
        "label": label,
        "warning": None,
    }
