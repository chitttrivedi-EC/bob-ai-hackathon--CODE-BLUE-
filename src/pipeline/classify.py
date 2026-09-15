"""
classify.py — Genuine-threat vs. false-positive classification stage.

Uses a scikit-learn RandomForestClassifier trained on features extracted
from correlated alert clusters. The model is persisted to disk with joblib
so Streamlit can reload it without retraining.

Feature engineering per cluster:
  - max_severity_score  (1-5 ordinal)
  - source_type_diversity  (number of distinct source types)
  - alert_count  (total alerts in cluster)
  - avg_similarity  (FAISS cosine similarity score)
  - cross_source_flag  (1 if >1 source type present)
  - has_intel_report  (1 if intel_report source present)
  - has_siem  (1 if siem source present)
  - has_satellite  (1 if satellite source present)
  - has_cyber_sensor  (1 if cyber_sensor source present)
  - cve_count  (number of unique CVEs in cluster — from combined_text heuristic)

The training set is built from the synthetic alerts' ground-truth labels
(is_false_positive). On the first run the model is trained; subsequent runs
load the persisted model.

LangGraph node: classify_node(state) -> state
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, List

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.schema import AlertCluster, SeverityLevel, SourceType
from src.db import get_session, upsert_cluster, ClusterRow

MODEL_PATH = os.getenv("CLASSIFIER_MODEL_PATH", "data/classifier_model.joblib")

_SEV_SCORE = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH:     4,
    SeverityLevel.MEDIUM:   3,
    SeverityLevel.LOW:      2,
    SeverityLevel.INFO:     1,
}


# ── Feature extraction ────────────────────────────────────────────────────────

def _extract_features(cluster: AlertCluster) -> List[float]:
    source_set = {s.value for s in cluster.source_types}
    cve_count  = cluster.combined_text.upper().count("CVE-")
    return [
        _SEV_SCORE.get(cluster.max_severity, 3),          # max_severity_score
        len(source_set),                                   # source_type_diversity
        cluster.alert_count,                               # alert_count
        cluster.avg_similarity,                            # avg_similarity
        1 if len(source_set) > 1 else 0,                  # cross_source_flag
        1 if "intel_report" in source_set else 0,          # has_intel_report
        1 if "siem"         in source_set else 0,          # has_siem
        1 if "satellite"    in source_set else 0,          # has_satellite
        1 if "cyber_sensor" in source_set else 0,          # has_cyber_sensor
        min(cve_count, 10),                                # cve_count (capped)
    ]


def _cluster_from_row(row: ClusterRow, _alert_rows: dict) -> AlertCluster:
    """Re-construct an AlertCluster from DB row for feature extraction."""
    src_types = []
    raw_sources = str(getattr(row, "source_types", "[]") or "[]")
    for s in json.loads(raw_sources):
        try:
            src_types.append(SourceType(s))
        except ValueError:
            pass
    try:
        max_sev = SeverityLevel(str(getattr(row, "max_severity", "medium") or "medium"))
    except ValueError:
        max_sev = SeverityLevel.MEDIUM

    return AlertCluster(
        cluster_id     = str(getattr(row, "cluster_id")),
        alert_ids      = json.loads(str(getattr(row, "alert_ids", "[]") or "[]")),
        source_types   = src_types,
        max_severity   = max_sev,
        avg_similarity = float(getattr(row, "avg_similarity", 0.0) or 0.0),
        combined_text  = str(getattr(row, "combined_text", "") or ""),
        alert_count    = int(getattr(row, "alert_count", 1) or 1),
    )


# ── Training ──────────────────────────────────────────────────────────────────

def _build_training_data(clusters: List[AlertCluster], alerts: List):
    """
    Build (X, y) from cluster features and ground-truth labels.
    Labels come from the majority vote of member alerts' is_false_positive flags.
    """
    # Build alert lookup  {alert_id: is_false_positive}
    alert_fp: dict = {}
    for a in alerts:
        fp = getattr(a, "is_false_positive", None)
        if fp is None and hasattr(a, "__dict__"):
            fp = a.__dict__.get("is_false_positive")
        alert_fp[a.id] = bool(fp)

    X, y = [], []
    labeled = []
    for cluster in clusters:
        # majority vote
        fp_flags = [alert_fp.get(aid, False) for aid in cluster.alert_ids]
        is_fp = (sum(fp_flags) / max(len(fp_flags), 1)) >= 0.5
        X.append(_extract_features(cluster))
        y.append(0 if is_fp else 1)   # 1 = genuine threat
        labeled.append(cluster)
    return X, y, labeled


def train_and_save(clusters: List[AlertCluster], alerts: List) -> object:
    X, y, _ = _build_training_data(clusters, alerts)

    if len(set(y)) < 2:
        print("[classify] WARNING: only one class in training data - adding synthetic samples")
        # Ensure at least one sample of each class
        minority_class = 0 if y.count(1) > y.count(0) else 1
        synthetic_fp = [1, 1, 3, 0.6, 0, 0, 0, 0, 0, 0]
        synthetic_tp = [5, 3, 4, 0.9, 1, 1, 1, 0, 1, 2]
        if minority_class == 0:
            X.append(synthetic_fp)
            y.append(0)
        else:
            X.append(synthetic_tp)
            y.append(1)

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X, y)

    # Cross-val score for reporting (only if both classes have >= 2 samples)
    min_class_count = min(y.count(0), y.count(1)) if len(set(y)) >= 2 else 0
    if min_class_count >= 2:
        cv_splits = min(5, min_class_count)
        try:
            scores = cross_val_score(clf, X, y, cv=cv_splits, scoring="f1")
            print(f"[classify] Cross-val F1: {scores.mean():.3f} +/- {scores.std():.3f}")
        except Exception:
            pass
    else:
        print("[classify] Small training sample size - fitted directly on available clusters")

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"[classify] Model saved -> {MODEL_PATH}")
    return clf


def load_model():
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    return None


# ── Prediction ────────────────────────────────────────────────────────────────

def classify_clusters(
    clusters: List[AlertCluster],
    alerts: List,
    retrain: bool = True,
) -> List[AlertCluster]:
    clf: Any = None
    if not retrain:
        clf = load_model()

    if clf is None:
        clf = train_and_save(clusters, alerts)

    scored = []
    with get_session() as session:
        for cluster in clusters:
            feats = [_extract_features(cluster)]
            proba = clf.predict_proba(feats)[0]
            # Index 1 = genuine threat probability
            threat_score = float(proba[1]) if len(proba) > 1 else float(proba[0])
            cluster.threat_score      = round(threat_score, 4)
            cluster.is_false_positive = threat_score < 0.35
            upsert_cluster(session, cluster)
            scored.append(cluster)

    scored.sort(key=lambda c: c.threat_score, reverse=True)

    fp_count = sum(1 for c in scored if c.is_false_positive)
    print(f"[classify] Scored {len(scored)} clusters | FP={fp_count} | TP={len(scored)-fp_count}")
    print(f"[classify] Top threat scores: {[round(c.threat_score,3) for c in scored[:5]]}")
    return scored


# ── LangGraph node ────────────────────────────────────────────────────────────

def classify_node(state: dict) -> dict:
    from src.schema import AlertCluster, NormalizedAlert
    clusters = [AlertCluster(**c) for c in state.get("clusters", [])]
    alerts   = [NormalizedAlert(**a) for a in state.get("alerts", [])]
    scored   = classify_clusters(clusters, alerts, retrain=True)
    return {
        **state,
        "clusters": [c.model_dump() for c in scored],
        "stage":    "map_attack",
    }
