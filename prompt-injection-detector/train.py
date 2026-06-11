"""Standalone script to train and save the ML classifier."""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.utils import class_weight

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.classifier import train  # noqa: E402
from data.training_data import (  # noqa: E402
    get_category_counts,
    get_training_data,
    get_training_data_with_metadata,
)

BENIGN_TEST_CASES = [
    ("How do I bypass a traffic jam?", "bypass"),
    ("What are the rules for chess?", "rules"),
    ("How do I access my email?", "access"),
    ("Tell me about encryption history", "encryption"),
    ("How do I override settings in VS Code?", "override"),
    ("What does the ignore() function do in Python?", "ignore"),
    ("How do I get root access on my Raspberry Pi?", "root"),
    ("Tell me about SQL injection for my security class", "injection"),
    ("What is a reverse proxy?", "reverse"),
    ("How do I kill a process in Linux?", "kill"),
    ("What is privilege escalation in career terms?", "privilege"),
    ("How do I drop a table in my dev database?", "drop"),
    ("Explain how malware works so I can protect myself", "malware"),
    ("How do I retrieve files from a REST API?", "retrieve"),
    ("Tell me about the history of hacking culture", "hacking"),
]

ML_FP_THRESHOLD = 0.45


def _print_top_features(pipeline, top_n: int = 10) -> None:
    vectorizer = pipeline.named_steps["tfidf"]
    classifier = pipeline.named_steps["clf"]
    feature_names = vectorizer.get_feature_names_out()
    coefs = classifier.coef_[0]
    top_indices = np.argsort(np.abs(coefs))[-top_n:][::-1]

    print(f"\nTop {top_n} most informative features:")
    for idx in top_indices:
        print(f"  {feature_names[idx]:<30} coef={coefs[idx]:+.4f}")


def _print_false_positive_report(pipeline) -> None:
    print("\n=== FALSE POSITIVE REPORT ===")
    passed = 0
    total = len(BENIGN_TEST_CASES)

    for text, keyword in BENIGN_TEST_CASES:
        proba = pipeline.predict_proba([text])[0]
        classes = list(pipeline.classes_)
        injection_idx = classes.index(1) if 1 in classes else int(classes[-1])
        probability = float(proba[injection_idx])
        status = "PASS" if probability < ML_FP_THRESHOLD else "FAIL"
        if probability < ML_FP_THRESHOLD:
            passed += 1
        print(f"  {text} | {probability:.3f} | {status} (keyword: {keyword})")

    print(f"\nTotal pass rate: {passed}/{total} benign cases correctly classified")


def main() -> None:
    X, y = get_training_data()
    _, _, categories = get_training_data_with_metadata()
    category_counts = get_category_counts()

    print(f"Loaded {len(X)} training samples ({sum(y)} threats, {len(y) - sum(y)} safe)")
    print("\nExamples per category:")
    for category, count in sorted(category_counts.items()):
        print(f"  {category}: {count}")

    classes = np.unique(y)
    weights = class_weight.compute_class_weight("balanced", classes=classes, y=y)
    class_weights = dict(zip(classes, weights))
    print("\nClass weights (balanced):")
    for label, weight in sorted(class_weights.items()):
        label_name = "threat" if label == 1 else "safe"
        print(f"  {label_name} ({label}): {weight:.4f}")

    X_train, X_test, y_train, y_test, cat_train, cat_test = train_test_split(
        X, y, categories, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = train(X_train, y_train)

    y_train_pred = pipeline.predict(X_train)
    y_test_pred = pipeline.predict(X_test)

    train_accuracy = accuracy_score(y_train, y_train_pred)
    test_accuracy = accuracy_score(y_test, y_test_pred)

    print(f"\nTrain accuracy: {train_accuracy:.4f}")
    print(f"Test accuracy:  {test_accuracy:.4f}")
    print("\nClassification report (test set):")
    print(classification_report(y_test, y_test_pred, target_names=["safe", "threat"]))

    print("Confusion matrix (test set):")
    cm = confusion_matrix(y_test, y_test_pred)
    print(f"  [[TN={cm[0][0]}, FP={cm[0][1]}],")
    print(f"   [FN={cm[1][0]}, TP={cm[1][1]}]]")

    print("\nPer-category detection on test set (regex-independent ML labels):")
    unique_cats = sorted({c for c in cat_test if c})
    for category in unique_cats:
        indices = [i for i, c in enumerate(cat_test) if c == category]
        if not indices:
            continue
        cat_y_true = [y_test[i] for i in indices]
        cat_y_pred = [y_test_pred[i] for i in indices]
        cat_acc = accuracy_score(cat_y_true, cat_y_pred)
        print(f"  {category}: {cat_acc:.4f} ({sum(cat_y_pred)}/{len(indices)} predicted threat)")

    _print_top_features(pipeline)
    _print_false_positive_report(pipeline)

    model_path = PROJECT_ROOT / "models" / "classifier.pkl"
    print(f"\nModel saved to {model_path}")


if __name__ == "__main__":
    main()
