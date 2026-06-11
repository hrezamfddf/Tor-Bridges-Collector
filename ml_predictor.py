#!/usr/bin/env python3
"""
ml_predictor.py — FEATURE 1: AI-Driven Bridge Blocking Predictor.

Trains a RandomForest classifier on historical OONI measurements from Iran
(probe_cc=IR) to predict the probability that a given bridge will be blocked
within the next 24 hours.

Feature vector (8 dimensions):
  0  transport_enc      int [0-5]   snowflake=0 webtunnel=1 obfs4=2 meek=3 vanilla=4 unknown=5
  1  port_risk          int [0-4]   443=0  80=1  8080=2  random_high=3  tor_ports=4
  2  cdn_present        float [0/1] 1 if any known CDN domain in bridge line
  3  days_first_seen    float       clamped to [0, 365]
  4  recurrence_rate    float       anomaly blocks per 30-day period (90-day window)
  5  dpi_risk_flag      float [0/1] 1 if iran_dpi_high_risk flag is set
  6  iran_asn           float [0/1] 1 if IP resolves to an Iranian ISP ASN
  7  ooni_anomaly_rate  float [0-1] fraction of recent measurements with anomaly

Label: 1 = will be blocked (iran_likely_blocked | iran_frequently_blocked | iran_asn_blocked)
       0 = likely reachable (iran_likely_working | iran_unknown + tcp_reachable)

The model is serialised to data/blocking_model.pkl and versioned via
data/model_metadata.json. On each CI run, the model is retrained on the
latest iran_results.json data and the updated blocking probabilities are
applied as a negative weight in the composite scoring formula:

  adjusted_composite = composite_score × (1.0 - 0.25 × predicted_block_prob)

CLI:
  python ml_predictor.py --train           Train/retrain and save model.
  python ml_predictor.py --train --apply   Train then rewrite composite scores.
  python ml_predictor.py --apply           Apply saved model to current results.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pickle
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

IRAN_RESULTS_PATH  = Path("bridge/iran_results.json")
LATEST_RESULTS_PATH = Path("data/latest-results.json")
MODEL_PATH         = Path("data/blocking_model.pkl")
METADATA_PATH      = Path("data/model_metadata.json")
Path("data").mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Iranian ASN set (mirrors Go internal/asn/iran_asns.go)
# ─────────────────────────────────────────────────────────────────────────────

IRAN_ASNS: set = {
    "AS12880", "AS16322", "AS44244", "AS25124", "AS197207", "AS58224",
    "AS48431", "AS43754", "AS31549", "AS49100", "AS39650", "AS24631",
    "AS56402", "AS47796", "AS60672", "AS48159", "AS29049", "AS42337",
    "AS50810", "AS34918",
}

CDN_PATTERNS = [
    "fastly.net", "cloudfront.net", "azureedge.net", "gstatic.com",
    "aspnetcdn.com", "arvancloud.com", "arvancloud.ir", "cdn.irimc.ir",
    "googlevideo.com",
]

TRANSPORT_ENCODING: Dict[str, int] = {
    "snowflake": 0, "webtunnel": 1, "obfs4": 2,
    "meek_lite": 3, "vanilla": 4, "unknown": 5,
}

BLOCKED_STATUSES = {"iran_likely_blocked", "iran_frequently_blocked", "iran_asn_blocked"}
WORKING_STATUSES = {"iran_likely_working"}


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction
# ─────────────────────────────────────────────────────────────────────────────

def _port_risk(port: int) -> int:
    if port == 443:
        return 0
    if port == 80:
        return 1
    if port in (8080, 8443):
        return 2
    if port in (9001, 9030, 9050):
        return 4
    return 3


def _cdn_present(raw: str) -> float:
    low = raw.lower()
    return 1.0 if any(p in low for p in CDN_PATTERNS) else 0.0


def _days_since(iso_ts: str) -> float:
    try:
        ts = datetime.fromisoformat(iso_ts)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        days = (datetime.now(timezone.utc) - ts).days
        return float(min(max(days, 0), 365))
    except Exception:
        return 30.0


def extract_features(record: Dict[str, Any]) -> List[float]:
    """Return the 8-dimensional feature vector for a bridge record."""
    transport   = record.get("transport", "unknown")
    port        = int(record.get("port", 0))
    raw         = record.get("line", record.get("raw", ""))
    flags       = record.get("flags", []) or []
    asn         = record.get("asn", "")
    recurrence  = float(record.get("recurrence_rate_per_30d", record.get("recurrence_rate", 0.0)) or 0.0)
    first_seen  = record.get("first_seen", "2020-01-01T00:00:00Z")

    # Feature 7: ooni_anomaly_rate estimated from composite score inversion
    # (true OONI measurement rate requires the full OONI history; here we
    # derive a proxy from the composite score's OONI dimension)
    ooni_factor   = float(record.get("ooni_factor", 0.5) or 0.5)
    anomaly_rate  = 1.0 - ooni_factor  # 0 = all clean, 1 = all blocked

    return [
        float(TRANSPORT_ENCODING.get(transport, 5)),
        float(_port_risk(port)),
        _cdn_present(raw),
        _days_since(first_seen),
        recurrence,
        1.0 if "iran_dpi_high_risk" in flags else 0.0,
        1.0 if asn in IRAN_ASNS else 0.0,
        anomaly_rate,
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Model training
# ─────────────────────────────────────────────────────────────────────────────

def load_labeled_data() -> Tuple[List[List[float]], List[int]]:
    """
    Load iran_results.json and latest-results.json, build (X, y) pairs.
    Returns (features, labels) where label 1 = blocked, 0 = not blocked.
    """
    X: List[List[float]] = []
    y: List[int]         = []

    sources = [IRAN_RESULTS_PATH, LATEST_RESULTS_PATH]
    seen: set = set()

    for path in sources:
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        records: List[Dict[str, Any]] = data.get("bridges", [])
        for r in records:
            line_key = r.get("line", r.get("bridge_line", ""))
            if line_key in seen:
                continue
            seen.add(line_key)

            status = r.get("iran_status", "")
            if status in BLOCKED_STATUSES:
                label = 1
            elif status in WORKING_STATUSES or (
                status == "iran_unknown" and r.get("tcp_reachable")
            ):
                label = 0
            else:
                continue  # skip ambiguous records

            X.append(extract_features(r))
            y.append(label)

    return X, y


def train(min_samples: int = 10) -> Optional[Dict[str, Any]]:
    """
    Train the RandomForest classifier and serialise it.
    Returns metadata dict or None if insufficient data.
    """
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_score
        import numpy as np
    except ImportError:
        log.error("scikit-learn not installed. Run: pip install scikit-learn")
        return None

    X, y = load_labeled_data()
    log.info(f"Training data: {len(X)} samples ({sum(y)} blocked, {len(y)-sum(y)} working)")

    if len(X) < min_samples:
        log.warning(
            f"Insufficient labeled data ({len(X)} samples, need ≥ {min_samples}). "
            "Skipping model training — will use neutral probability 0.5."
        )
        return {"status": "insufficient_data", "samples": len(X)}

    import numpy as np  # already imported above but explicit here for clarity

    X_arr = np.array(X, dtype=float)
    y_arr = np.array(y, dtype=int)

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=8,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",  # handle imbalanced blocked/working ratio
    )
    clf.fit(X_arr, y_arr)

    # Cross-validated accuracy
    cv_scores = cross_val_score(clf, X_arr, y_arr, cv=min(5, len(X) // 2), scoring="roc_auc")
    roc_auc = float(cv_scores.mean())

    # Feature importances
    feature_names = [
        "transport_enc", "port_risk", "cdn_present", "days_first_seen",
        "recurrence_rate", "dpi_risk_flag", "iran_asn", "ooni_anomaly_rate",
    ]
    importances = {
        name: round(float(imp), 4)
        for name, imp in zip(feature_names, clf.feature_importances_)
    }

    # Persist model
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)

    existing_meta = {}
    if METADATA_PATH.exists():
        try:
            existing_meta = json.loads(METADATA_PATH.read_text())
        except Exception:
            pass

    version = int(existing_meta.get("version", 0)) + 1
    metadata: Dict[str, Any] = {
        "trained_at":   datetime.now(timezone.utc).isoformat(),
        "version":      version,
        "samples":      len(X),
        "blocked":      int(sum(y)),
        "working":      int(len(y) - sum(y)),
        "roc_auc_cv":   round(roc_auc, 4),
        "feature_importances": importances,
        "status":       "ok",
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2))
    log.info(f"Model v{version} trained — ROC-AUC={roc_auc:.3f}, {len(X)} samples.")
    return metadata


# ─────────────────────────────────────────────────────────────────────────────
# Inference
# ─────────────────────────────────────────────────────────────────────────────

def load_model() -> Optional[Any]:
    if not MODEL_PATH.exists():
        return None
    try:
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    except Exception as exc:
        log.warning(f"Cannot load model: {exc}")
        return None


def predict_blocking_prob(model: Any, record: Dict[str, Any]) -> float:
    """
    Return the probability ∈ [0.0, 1.0] that this bridge will be blocked
    within the next 24 hours. Returns 0.5 (neutral) when no model is loaded.
    """
    if model is None:
        return 0.5
    try:
        import numpy as np
        feats = np.array([extract_features(record)], dtype=float)
        proba = model.predict_proba(feats)[0]
        # proba shape: (2,) where index 1 = P(blocked)
        return float(proba[1]) if len(proba) > 1 else 0.5
    except Exception as exc:
        log.debug(f"Prediction error: {exc}")
        return 0.5


# ─────────────────────────────────────────────────────────────────────────────
# Apply predictions to composite scores
# ─────────────────────────────────────────────────────────────────────────────

AI_WEIGHT = 0.25  # how much the ML prediction influences the final score


def apply_predictions_to_results(model: Any) -> int:
    """
    Read latest-results.json, adjust each bridge's composite_score by the
    AI blocking prediction, and write the updated file back.
    Returns the number of records updated.
    """
    if not LATEST_RESULTS_PATH.exists():
        log.warning("latest-results.json not found — skipping apply step.")
        return 0

    data = json.loads(LATEST_RESULTS_PATH.read_text(encoding="utf-8"))
    records: List[Dict[str, Any]] = data.get("bridges", [])

    updated = 0
    for r in records:
        block_prob = predict_blocking_prob(model, r)
        original   = float(r.get("composite_score", 0.5))
        # Negative weight: high blocking probability deflates the composite score.
        adjusted   = round(original * (1.0 - AI_WEIGHT * block_prob), 4)
        r["predicted_block_prob"] = round(block_prob, 4)
        r["composite_score"]      = adjusted
        r["composite_score_orig"] = original
        updated += 1

    # Re-sort by updated composite score
    records.sort(key=lambda x: x.get("composite_score", 0.0), reverse=True)
    data["bridges"]              = records
    data["ml_model_applied"]     = True
    data["ml_ai_weight"]         = AI_WEIGHT
    data["ml_applied_at"]        = datetime.now(timezone.utc).isoformat()

    LATEST_RESULTS_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    log.info(f"AI predictions applied to {updated} bridge records.")
    return updated


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="TorShield-IR ML Blocking Predictor")
    parser.add_argument("--train",  action="store_true", help="Train/retrain the model")
    parser.add_argument("--apply",  action="store_true", help="Apply model to current results")
    args = parser.parse_args()

    if not args.train and not args.apply:
        parser.print_help()
        sys.exit(0)

    model = None

    if args.train:
        log.info("═══ ML Predictor: Training ══════════════════════════════")
        metadata = train()
        if metadata and metadata.get("status") == "ok":
            model = load_model()
        log.info("Training complete.")

    if args.apply:
        log.info("═══ ML Predictor: Applying to results ═══════════════════")
        if model is None:
            model = load_model()
        if model is None:
            log.warning("No trained model available — composite scores unchanged.")
        else:
            apply_predictions_to_results(model)

    log.info("═══ ML Predictor done ═══════════════════════════════════════")


if __name__ == "__main__":
    main()
