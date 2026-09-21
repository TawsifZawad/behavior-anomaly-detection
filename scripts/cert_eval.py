"""
CERT r4.2 insider-threat EVALUATION for the behavioural Isolation Forest.

Where scripts.cert_train only *trains* on CERT normal behaviour, this
script *measures* how well the model separates genuine normal user-days
from the seeded malicious-insider user-days, using the official CERT answer
files as ground truth. This turns the eval's "normal" side from synthetic
demo users into ~1,000 realistic CERT users and hundreds of thousands of
real sessions.

Ground truth: the answer files (answers.tar.bz2) list every malicious log
line with its exact date and user, so a session (user, day) is labelled
malicious (1) when it contains a real malicious event, else normal (0).

Honest UEBA protocol: the Isolation Forest is trained on NORMAL sessions
only (a random 80%), then tested on the held-out 20% of normals plus ALL
malicious sessions - so no malicious behaviour is ever seen in training.

Needs, under data/datasets/cert/:
    logon.csv  device.csv  file.csv          (from r4.2.tar.bz2)
    answers/...                              (from answers.tar.bz2)

Usage:
    python -m scripts.cert_eval
"""

import os
import sys
import csv
import glob
import json
from datetime import datetime

import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
)

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

import scripts.cert_train as ct
from models.feature_vector import ML_MODEL_FEATURES, CERT_EXTRA_FEATURES
from reporting.report_generator import ReportGenerator

ANSWERS = os.path.join(ct.DATA_DIR, "answers")
REPORT_DIR = os.path.join("reports", "cert")


def load_malicious_days():
    """Every (user, date) that contains a real malicious event in r4.2."""
    files = (glob.glob(os.path.join(ANSWERS, "r4.2-*.csv"))
             + glob.glob(os.path.join(ANSWERS, "r4.2-*", "*.csv")))
    mal = set()
    for path in files:
        with open(path, newline="", encoding="utf-8", errors="ignore") as f:
            for row in csv.reader(f):
                if len(row) < 4:
                    continue
                # answer line: type, id, date, user, pc, ...
                try:
                    d = datetime.strptime(
                        row[2].strip(), "%m/%d/%Y %H:%M:%S").date()
                except (ValueError, IndexError):
                    continue
                mal.add((row[3].strip(), d))
    return mal


def stream_sessions():
    """Populate cert_train's per-(user,day) accumulators, then yield each
    session as (user, date, feature-dict). E-mail/web sources are streamed
    when present so the extended (+ e-mail/web) feature set can be scored."""
    for kind in ("logon", "device", "file", "http", "email"):
        path = ct.FILES.get(kind)
        if path and os.path.exists(path):
            ct._stream(path, kind)

    for k in ct.tot:
        user, day = k
        total = ct.tot[k]
        lo = ct.minh.get(k, 0)
        hi = ct.maxh.get(k, 0)
        active = max(1, hi - lo)
        login_h = ct.first_logon.get(k, lo)
        logout_h = ct.last_logoff.get(k, hi)
        sent = ct.email_sent.get(k, 0)
        feat = {
            "login_hour": float(login_h),
            "logout_hour": float(logout_h),
            "session_span": float(max(0, logout_h - login_h)),
            "off_hours_ratio": (ct.off[k] / total) if total else 0.0,
            "weekend_activity": ct.weekend.get(k, 0),
            "event_rate": total / active,
            "active_hours": int(hi - lo),
            "process_start": 0,
            "file_access": ct.file_cnt.get(k, 0),
            "distinct_processes": 0,
            "file_to_process_ratio": 0.0,
            "failed_login": 0,
            "login_attempts": ct.logon_cnt.get(k, 0),
            "off_hours_logon": ct.off_logon.get(k, 0),
            "distinct_file_types": len(ct.file_types.get(k, ())),
            "usb_events": ct.usb_cnt.get(k, 0),
            "removable_file_events": ct.removable.get(k, 0),
            "distinct_ips": len(ct.pcs.get(k, ())),
            # --- e-mail / web (benchmark-only) ---
            "web_events": ct.web_cnt.get(k, 0),
            "distinct_web_domains": len(ct.web_domains.get(k, ())),
            "email_sent": sent,
            "external_email_ratio": (ct.email_ext.get(k, 0) / sent)
            if sent else 0.0,
            "email_attachments": ct.email_attach.get(k, 0),
        }
        yield user, pd.Timestamp(day).date(), feat


def _score_featureset(X, y, tr_norm, test_idx):
    """Train IF on the normal-only training rows and return anomaly scores
    for the test rows (higher = more anomalous), for one feature matrix."""
    model = make_pipeline(
        StandardScaler(),
        IsolationForest(n_estimators=300, contamination=0.02,
                        random_state=42, n_jobs=-1),
    )
    model.fit(X[tr_norm])
    return -model.decision_function(X[test_idx])


def main():
    if not os.path.exists(os.path.join(ANSWERS, "insiders.csv")):
        print("CERT answers not found. Download answers.tar.bz2 and extract "
              "it into " + ANSWERS + "/ first "
              "(https://ndownloader.figshare.com/files/24857828).")
        return
    if not os.path.exists(ct.FILES["logon"]):
        print("CERT logon.csv not found in " + ct.DATA_DIR + "/.")
        return

    print("Loading malicious ground truth ...")
    mal = load_malicious_days()
    print(f"  malicious (user, day) sessions: {len(mal)} "
          f"from {len(set(u for u, _ in mal))} insiders")

    print("Streaming CERT sessions and labelling ...")
    EXT_FEATURES = ML_MODEL_FEATURES + CERT_EXTRA_FEATURES
    X, X_ext, y, users = [], [], [], []
    for user, day, feat in stream_sessions():
        X.append([feat[f] for f in ML_MODEL_FEATURES])
        X_ext.append([feat[f] for f in EXT_FEATURES])
        y.append(1 if (user, day) in mal else 0)
        users.append(user)
    X = np.array(X, dtype=float)
    X_ext = np.array(X_ext, dtype=float)
    y = np.array(y, dtype=int)
    users = np.array(users)
    print(f"  sessions: {len(y):,}  normal: {(y == 0).sum():,}  "
          f"malicious: {(y == 1).sum()}")

    if (y == 1).sum() == 0:
        print("No malicious sessions matched - check the answer files.")
        return

    # Train on NORMAL only (80%); test on held-out normals + ALL malicious.
    idx = np.arange(len(y))
    normal_idx = idx[y == 0]
    mal_idx = idx[y == 1]
    tr_norm, te_norm = train_test_split(
        normal_idx, test_size=0.2, random_state=42)
    test_idx = np.concatenate([te_norm, mal_idx])

    print(f"Training Isolation Forest on {len(tr_norm):,} normal sessions ...")
    model = make_pipeline(
        StandardScaler(),
        IsolationForest(n_estimators=300, contamination=0.02,
                        random_state=42, n_jobs=-1),
    )
    model.fit(X[tr_norm])

    y_true = y[test_idx]
    test_users = users[test_idx]
    pred = model.predict(X[test_idx])
    y_pred = np.where(pred == -1, 1, 0)
    y_score = -model.decision_function(X[test_idx])

    total_mal = int((y_true == 1).sum())
    print("\n===== CERT r4.2 Insider-Threat Evaluation =====")
    print(f"Test sessions : {len(y_true):,}  "
          f"(normal {(y_true == 0).sum():,}, malicious {total_mal})")
    print("\n-- Threshold-independent (the fair headline for 1.5%-rare "
          "insiders) --")
    print(f"ROC-AUC   : {roc_auc_score(y_true, y_score):.4f}   "
          "(1.0 perfect, 0.5 random)")

    # Detection rate at an investigation budget: rank all test sessions by
    # anomaly score and ask how many insider-days fall in the top X% an
    # analyst would actually review. This is how insider-threat datasets
    # are evaluated in practice - raw F1 at a fixed cut is misleading when
    # positives are 1.5% of the data.
    order = np.argsort(-y_score)
    mal_sorted = y_true[order]
    users_sorted = test_users[order]
    n = len(y_true)
    total_insiders = len(set(test_users[y_true == 1]))
    print("\n-- Detection rate at investigation budget (rank by anomaly "
          "score) --")
    print(f"   (per-day = of {total_mal} malicious user-days; per-insider = "
          f"of {total_insiders} insiders, caught if ANY of their days is "
          "flagged)")
    budgets = {}
    for pct in (1, 5, 10, 20):
        k = max(1, int(n * pct / 100))
        caught = int(mal_sorted[:k].sum())
        rate = caught / total_mal
        top_mal_users = set(users_sorted[:k][mal_sorted[:k] == 1])
        ins_rate = len(top_mal_users) / total_insiders
        budgets[f"top_{pct}pct"] = round(rate, 4)
        budgets[f"top_{pct}pct_insiders"] = round(ins_rate, 4)
        print(f"  review top {pct:2d}% ({k:,} sessions): "
              f"per-day {caught}/{total_mal} ({rate*100:.1f}%)  |  "
              f"per-insider {len(top_mal_users)}/{total_insiders} "
              f"({ins_rate*100:.1f}%)")

    print("\n-- At the default Isolation-Forest cut (2% contamination) --")
    print(f"Accuracy  : {accuracy_score(y_true, y_pred):.4f}   "
          "(misleadingly high - 98.5% of sessions are normal)")
    print(f"Precision : {precision_score(y_true, y_pred, zero_division=0):.4f}"
          f"   Recall : {recall_score(y_true, y_pred, zero_division=0):.4f}"
          f"   F1 : {f1_score(y_true, y_pred, zero_division=0):.4f}")

    # ---- Base vs. extended (+ e-mail/web) feature set ------------------
    # The future-work claim is that e-mail/web behaviour improves per-day
    # insider detection. Measure it honestly: same protocol, same split,
    # base ROC-AUC vs. ROC-AUC with the e-mail/web features added.
    base_auc = roc_auc_score(y_true, y_score)
    email_web = {}
    ext_has_signal = not np.allclose(
        X_ext[:, len(ML_MODEL_FEATURES):], 0.0)
    if ext_has_signal:
        ext_score = _score_featureset(X_ext, y, tr_norm, test_idx)
        ext_auc = roc_auc_score(y_true, ext_score)
        ext_order = np.argsort(-ext_score)
        ext_mal_sorted = y_true[ext_order]
        ext_budget = {}
        for pct in (5, 10, 20):
            kk = max(1, int(n * pct / 100))
            ext_budget[f"top_{pct}pct"] = round(
                int(ext_mal_sorted[:kk].sum()) / total_mal, 4)
        email_web = {
            "base_roc_auc": round(base_auc, 4),
            "extended_roc_auc": round(ext_auc, 4),
            "delta_roc_auc": round(ext_auc - base_auc, 4),
            "extended_detection_at_budget": ext_budget,
            "extra_features": CERT_EXTRA_FEATURES,
        }
        print("\n-- E-mail/web features (base vs. extended feature set) --")
        print(f"   base ROC-AUC     : {base_auc:.4f}")
        print(f"   + e-mail/web     : {ext_auc:.4f}  "
              f"(delta {ext_auc - base_auc:+.4f})")
    else:
        print("\n-- E-mail/web features: http.csv / email.csv absent or "
              "empty; extended comparison skipped. --")

    report = ReportGenerator(output_dir=REPORT_DIR)
    metrics = report.generate(y_true, y_pred, y_score)
    metrics["dataset"] = "CERT r4.2 (insider threat)"
    metrics["users"] = 1000
    metrics["insiders"] = len(set(u for u, _ in mal))
    metrics["sessions_total"] = int(len(y))
    metrics["normal_sessions"] = int((y == 0).sum())
    metrics["malicious_sessions"] = int((y == 1).sum())
    metrics["detection_at_budget"] = budgets
    if email_web:
        metrics["email_web"] = email_web
    with open(os.path.join(REPORT_DIR, "metrics.json"), "w",
              encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nArtifacts written to {REPORT_DIR}/ "
          "(metrics.json, confusion_matrix.png, roc_curve.png)")


if __name__ == "__main__":
    main()
