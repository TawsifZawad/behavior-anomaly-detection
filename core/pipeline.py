"""
Reusable detection-pipeline steps shared by the bads CLI.

Every command (learn / detect / replay / evaluate / dashboard / demo)
composes these functions instead of duplicating the flow. There is no
global development/production MODE any more: whether a session comes from
live collectors or a sample events file is decided by which function the
command calls, not by a config flag.
"""

import os
import platform

from core.event import Event
from core.database import (
    create_tables,
    insert_event,
    insert_events_bulk,
    get_all_events,
    get_events_by_user,
    clear_events,
)

from feature_engine.aggregator import EventAggregator
from feature_engine.extractor import FeatureExtractor
from feature_engine.baseline import BaselineManager
from feature_engine.comparator import BehaviorComparator
from feature_engine.dataset_builder import DatasetBuilder
from feature_engine.dataset_generator import DatasetGenerator

from behavior_detection.correlation_engine import CorrelationEngine
from behavior_detection.risk_engine import RiskEngine
from behavior_detection.analyzer import BehaviorAnalyzer
from behavior_detection.decision_engine import DecisionEngine
from behavior_detection.alert_manager import AlertManager

from ml.trainer import BehaviorTrainer
from ml.predictor import BehaviorPredictor
from ml.evaluator import ModelEvaluator

from utils.data_loader import load_sample_events

from config.settings import LEARNING_MODE

# Two independent models so live/own learning never degrades the
# reproducible sample-attack detection used by analyze / demo.
SAMPLE_MODEL = "ml/model.joblib"          # analyze / replay / demo
OWN_MODEL = "ml/model_own.joblib"         # own / watch (this machine)
OWN_DATASET = "data/ml_own_dataset.csv"   # this machine's learned normal


# ---------------------------------------------------------------------
# Collectors (imported lazily inside functions that need them so the
# CLI still runs on a machine missing an OS-specific dependency).
# ---------------------------------------------------------------------

def get_os_collector():
    os_name = platform.system()

    if os_name == "Windows":
        from collectors.windows_collector import WindowsCollector
        return WindowsCollector()

    if os_name == "Linux":
        from collectors.ubuntu_collector import UbuntuCollector
        return UbuntuCollector()

    if os_name == "Darwin":
        from collectors.mac_collector import MacCollector
        return MacCollector()

    raise RuntimeError(f"Unsupported operating system: {os_name}")


# ---------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------

def _events_from_db():
    """Read every stored event back as Event objects."""
    rows = get_all_events()
    return [
        Event(
            event_record_id=row[1],
            timestamp=row[2],
            username=row[3],
            os=row[4],
            event_type=row[5],
            source=row[6],
            ip=row[7],
            details=row[8],
        )
        for row in rows
    ]


# Base telemetry that is not, by itself, evidence of a threat. Everything
# else in a user's event stream is a derived indicator worth showing.
_BENIGN_EVENT_TYPES = {
    "LOGIN_SUCCESS", "LOGIN_FAILED", "LOGOUT",
    "PROCESS_START", "FILE_ACCESS", "USB_INSERT", "USB_REMOVE",
}

# Human-readable label per indicator event type.
_INDICATOR_LABELS = {
    "ENCODED_COMMAND": "Encoded PowerShell",
    "EXECUTION_POLICY_BYPASS": "Execution-policy bypass",
    "POWERSHELL_START": "PowerShell / interpreter",
    "HIDDEN_PROCESS": "Hidden window",
    "EXECUTION_FROM_TEMP": "Run from temp/download",
    "UNSIGNED_BINARY": "Unsigned binary",
    "DOUBLE_EXTENSION": "Double extension",
    "OFFICE_SPAWNED_SHELL": "Office spawned shell",
    "USB_EXECUTABLE_RUN": "Executable from USB",
    "SUSPICIOUS_DOWNLOAD": "Suspicious download",
    "DOWNLOAD_EXECUTE": "Download-and-execute",
    "INTERNET_DOWNLOAD": "Internet download",
    "CERTUTIL_DOWNLOAD": "certutil download",
    "BITSADMIN_DOWNLOAD": "bitsadmin transfer",
    "RUNDLL32_NETWORK": "rundll32 network",
    "REGSVR32_REMOTE_SCRIPT": "regsvr32 remote script",
    "MSHTA_REMOTE_SCRIPT": "mshta remote script",
    "PRIVILEGE_ESCALATION": "Privilege escalation",
    "SUDO_ABUSE": "sudo abuse",
    "NMAP_SCAN": "Network scan tool",
    "HYDRA_BRUTEFORCE": "Brute-force tool",
    "SSH_BRUTEFORCE": "SSH brute force",
    "REVERSE_SHELL": "Reverse shell",
    "RANSOMWARE_BEHAVIOR": "Ransomware / recovery wipe",
    "SENSITIVE_FILE_ACCESS": "Credential/secret access",
    "PERSISTENCE_CREATED": "Persistence",
    "OSASCRIPT_SHELL": "AppleScript shell",
    "NETWORK_ALERT": "Network IDS alert",
    "PORT_SCAN": "Port scan (network)",
    "MALICIOUS_IP_CONTACT": "Malicious/C2 host",
    "DATA_EXFILTRATION": "Data exfiltration",
    "SIEM_ALERT": "Wazuh SIEM alert",
}


def _format_indicator(event_type, details):
    """Turn an event type + its details into a readable evidence line,
    stripping internal bookkeeping (score=..) so the actual command /
    file / signature remains."""
    label = _INDICATOR_LABELS.get(event_type, event_type)

    parts = [p.strip() for p in (details or "").split("|")]
    parts = [p for p in parts if p and not p.lower().startswith("score=")]
    evidence = " | ".join(parts).strip()

    return f"{label}: {evidence}" if evidence else label


def indicators_for_user(username, limit=12):
    """Concrete evidence (harmful commands / files / signatures) behind a
    user's alert, de-duplicated, for display in the dashboard."""
    seen = []
    for event_type, details, _source, _ip in get_events_by_user(username):
        if event_type in _BENIGN_EVENT_TYPES:
            continue
        line = _format_indicator(event_type, details)
        if line not in seen:
            seen.append(line)
        if len(seen) >= limit:
            break
    return seen


def _feature_vectors(event_objects):
    aggregator = EventAggregator()
    extractor = FeatureExtractor()

    groups = aggregator.group_by_user(event_objects)

    vectors = []
    for _username, events in groups.items():
        vectors.append(extractor.extract(events))
    return vectors


# ---------------------------------------------------------------------
# Baseline learning + model training
# ---------------------------------------------------------------------

def learn_baseline(baseline_file):
    """
    Establish per-user baselines and (re)train the anomaly model from a
    body of NORMAL behavior. Returns the baseline feature vectors.
    """

    create_tables()

    print("\n===== Baseline Learning =====")

    clear_events()

    insert_events_bulk(load_sample_events(baseline_file))

    feature_vectors = _feature_vectors(_events_from_db())

    baseline = BaselineManager()
    dataset_builder = DatasetBuilder()

    if LEARNING_MODE:
        for features in feature_vectors:
            baseline.save(features)
            dataset_builder.append(features, label=0)
        print("Baseline updated and real behavior appended to training set.")
    else:
        print("Learning mode OFF: baseline left unchanged.")

    _train_model(feature_vectors)

    return feature_vectors


def ensure_model(baseline_file=None):
    """
    Guarantee a trained model + sample baselines exist. Trains from the
    sample baseline the first time (so both Own and Analyze work on a
    fresh checkout); a no-op once ml/model.joblib is present.
    """
    from config.settings import BASELINE_EVENT_FILE

    if os.path.exists("ml/model.joblib"):
        return

    print("No model yet — training from the sample baseline...")
    learn_baseline(baseline_file or BASELINE_EVENT_FILE)


def establish_baselines(feature_vectors):
    """
    Save a baseline for any user that does not have one yet (the first
    Own scan of a machine), so subsequent scans can add deviation
    analysis on top of the always-on threat detection. Returns the list
    of usernames that were newly baselined.
    """
    baseline = BaselineManager()

    new_users = []

    for features in feature_vectors:
        if baseline.load(features.username) is None:
            baseline.save(features)
            new_users.append(features.username)
            print(
                f"Baseline established for {features.username} from this "
                f"session (deviation detection active from the next scan)."
            )

    return new_users


def _looks_benign(features):
    """A session with no context-threat feature set is treated as normal
    and safe to learn from."""
    from feature_engine.dataset_generator import DatasetGenerator
    return all(
        getattr(features, name, 0) == 0
        for name in DatasetGenerator.THREAT_FEATURES
    )


def _jitter_normal(features):
    """A slightly varied copy of a benign feature vector (volume features
    only) to seed the model with this machine's normal range."""
    import random
    from dataclasses import replace
    # Wide multiplicative range so the learned "normal" tolerates the
    # large run-to-run swing in process / file volume on a real machine.
    return replace(
        features,
        process_start=max(
            0, int(features.process_start * random.uniform(0.3, 2.2))
        ),
        file_access=max(
            0, int(features.file_access * random.uniform(0.3, 2.2))
        ),
        failed_login=max(0, features.failed_login + random.randint(-1, 1)),
    )


def learn_own_normal(feature_vectors, samples=120):
    """
    Teach a SEPARATE own-model this machine's normal so benign live scans
    stop reading as anomalies — without ever touching the sample model /
    dataset used by analyze (so reproducible attack detection is
    preserved). Only benign sessions are learned. Called on a machine's
    first Own scan.
    """
    builder = DatasetBuilder(OWN_DATASET)

    learned = False
    for features in feature_vectors:
        if not _looks_benign(features):
            continue
        builder.append(features, label=0)
        for _ in range(samples):
            builder.append(_jitter_normal(features), label=0)
        learned = True

    if learned:
        print("Learning this machine's normal behavior for the model...")
        BehaviorTrainer().train(
            dataset_path=OWN_DATASET, model_path=OWN_MODEL
        )
        print("Model updated — benign scans will read as NORMAL next time.")


def _train_model(baseline_feature_vectors):
    """
    Train on accumulated real behavior; bootstrap with synthetic
    jittered-normal + attack samples when too little real data exists.
    """

    print("\n===== Training ML Model =====")

    trainer = BehaviorTrainer()

    try:
        trainer.train()
        print("Trained on real behavioral data.")
    except ValueError as error:
        print(f"Real data insufficient ({error}). Bootstrapping...")
        generator = DatasetGenerator()
        for features in baseline_feature_vectors:
            generator.generate(features, samples=200)
        generator.save()
        trainer.train()


# ---------------------------------------------------------------------
# Session acquisition (live vs. sample file)
# ---------------------------------------------------------------------

def _is_windows_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True  # non-Windows or undetectable: don't nag


def collect_live(username=None, include_sensors=True):
    """
    Populate the DB from live host telemetry, and — when include_sensors
    is set — the LIVE Suricata / Wazuh feeds configured in settings
    (LIVE_SURICATA_EVE_FILE / LIVE_WAZUH_ALERTS_FILE). Those default to
    blank, so on a machine without Suricata/Wazuh (or before they are
    configured) own/live simply run host-only. The reproducible `analyze`
    demo reads the separate SAMPLE feeds and is unaffected.
    """

    create_tables()
    clear_events()

    if platform.system() == "Windows" and not _is_windows_admin():
        print(
            "  NOTE: not running as Administrator — Windows host logs may "
            "be limited.\n"
            "        For a full scan, right-click bads.exe -> "
            "'Run as administrator'.\n"
        )

    # Host collector failures (permissions, missing deps) must not abort
    # the scan — the network / SIEM planes are still collected below.
    try:
        collector = get_os_collector()
        collector.collect()
    except Exception as exc:  # noqa: BLE001
        print(f"  [!] Host collection unavailable: {exc}")

    import getpass
    user = username or getpass.getuser()

    if include_sensors:
        from config.settings import (
            LIVE_SURICATA_EVE_FILE, LIVE_WAZUH_ALERTS_FILE,
        )

        if LIVE_SURICATA_EVE_FILE:
            try:
                from collectors.suricata_collector import SuricataCollector
                SuricataCollector(
                    eve_path=LIVE_SURICATA_EVE_FILE
                ).collect(username=user)
            except Exception as exc:
                print(f"Suricata collection skipped: {exc}")

        if LIVE_WAZUH_ALERTS_FILE:
            try:
                from collectors.wazuh_collector import WazuhCollector
                WazuhCollector(
                    alerts_path=LIVE_WAZUH_ALERTS_FILE
                ).collect(username=user)
            except Exception as exc:
                print(f"Wazuh collection skipped: {exc}")

    return _feature_vectors(_events_from_db())


def load_session_file(events_file, network_file=None, siem_file=None,
                      attribute_to=None):
    """
    Populate the DB from a sample host events file, optionally joined with
    Suricata and Wazuh sample telemetry attributed to `attribute_to` so
    the cross-plane correlation chains can fire in a reproducible demo.
    """

    create_tables()
    clear_events()

    insert_events_bulk(load_sample_events(events_file))

    if network_file:
        try:
            from collectors.suricata_collector import SuricataCollector
            SuricataCollector(eve_path=network_file).collect(
                username=attribute_to, reset=True
            )
        except Exception as exc:
            print(f"Suricata replay skipped: {exc}")

    if siem_file:
        try:
            from collectors.wazuh_collector import WazuhCollector
            WazuhCollector(alerts_path=siem_file).collect(
                username=attribute_to, reset=True
            )
        except Exception as exc:
            print(f"Wazuh replay skipped: {exc}")

    return _feature_vectors(_events_from_db())


# ---------------------------------------------------------------------
# Analysis (comparison + correlation + risk + ML + decision + alert)
# ---------------------------------------------------------------------

def analyze(feature_vectors, is_live=False, model_path=SAMPLE_MODEL):
    """Run the full detection pipeline over each user's feature vector."""

    baseline = BaselineManager()
    comparator = BehaviorComparator()
    correlation_engine = CorrelationEngine()
    risk_engine = RiskEngine()
    analyzer = BehaviorAnalyzer()
    # Fall back to the sample model if a machine-specific one isn't
    # trained yet (e.g. the very first Own scan).
    if not os.path.exists(model_path):
        model_path = SAMPLE_MODEL
    predictor = BehaviorPredictor(model_path)
    decision_engine = DecisionEngine()
    alert_manager = AlertManager()
    dataset_builder = DatasetBuilder()

    summary = {"total": 0, "known": 0, "new": 0, "flagged": 0, "safe": 0}
    sessions = []

    for features in feature_vectors:

        user = baseline.load(features.username)
        is_new = user is None

        summary["total"] += 1
        if is_new:
            summary["new"] += 1
        else:
            summary["known"] += 1

        print(f"\n===== {features.username} =====")

        if user is None:
            # No baseline yet: skip Tier-1 deviation (empty comparison)
            # but still run the baseline-independent threat detection
            # (context rules + correlation + ML), so a first-ever scan
            # still surfaces real threats.
            comparison = {}
            print("(No baseline yet — threat detection only; "
                  "deviation analysis begins once a baseline is learned.)")
        else:
            comparison = comparator.compare(features, user)

        correlations = correlation_engine.analyze(comparison, features)

        score, reasons = risk_engine.calculate(comparison, features)
        level = analyzer.get_risk_level(score)

        label, anomaly_score = predictor.predict(features)

        final_status = decision_engine.decide(score, label, correlations)

        print(f"Risk Score : {score}  ({level})")
        print(f"ML         : {label} (anomaly score {anomaly_score:.0f}/100)")
        print(f"Decision   : {final_status}")

        if correlations:
            print("Correlations:")
            for item in correlations:
                print(f"  - {item['name']} [{item['severity']}]")

        if reasons:
            print("Reasons:")
            for reason in reasons:
                print(f"  - {reason}")

        # ML explanation: which behaviours deviated from the learned
        # normal (the model's own reasoning via its scaler).
        ml_deviations = predictor.behavioral_deviations(features)
        if label == "ANOMALY" and ml_deviations:
            print("Behavioral deviations (ML):")
            for dev in ml_deviations:
                print(f"  ~ {dev['text']}")

        if final_status in ("SAFE", "NORMAL"):
            summary["safe"] += 1
        else:
            summary["flagged"] += 1

        # Record this session's behavioural features into the rolling
        # per-user history, so the dashboard can draw a recent trend. The
        # de-dup inside append_history keeps repeated demo runs clean.
        try:
            from core.history import append_history
            from models.feature_vector import ML_MODEL_FEATURES
            append_history(
                features.username,
                {f: getattr(features, f, 0) for f in ML_MODEL_FEATURES},
            )
        except Exception:
            pass

        # Record EVERY session (not just alerts) so the dashboard can
        # show live monitoring status even when a scan is benign.
        sessions.append({
            "username": features.username,
            "final_status": final_status,
            "risk_score": score,
            "risk_level": level,
            "ml_prediction": label,
            "ml_score": anomaly_score,
            "ml_deviations": [d["text"] for d in ml_deviations],
            "is_new": is_new,
        })

        if final_status in ("CRITICAL", "SUSPICIOUS"):
            indicators = indicators_for_user(features.username)
            if indicators:
                print("Indicators:")
                for indicator in indicators:
                    print(f"  * {indicator}")
            alert_manager.create_alert(
                username=features.username,
                risk_score=score,
                risk_level=level,
                ml_prediction=label,
                final_status=final_status,
                reasons=reasons,
                correlations=correlations,
                indicators=indicators,
                ml_score=anomaly_score,
                ml_deviations=[d["text"] for d in ml_deviations],
            )

        # Continuous learning: only grow the training set from live,
        # benign sessions — never learn an attack as normal.
        if is_live and LEARNING_MODE and final_status in ("SAFE", "NORMAL"):
            dataset_builder.append(features, label=0)
            print("Session recorded as normal training data.")

    # Persist the run summary + every session for the dashboard, so live
    # monitoring shows current status even when nothing alerted.
    try:
        import json
        from config.settings import REPORTS_DIR
        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(os.path.join(REPORTS_DIR, "summary.json"), "w",
                  encoding="utf-8") as f:
            json.dump(summary, f)
        # Most-anomalous first; cap so a 100-user run stays readable.
        sessions.sort(key=lambda s: s["ml_score"] or 0, reverse=True)
        with open(os.path.join(REPORTS_DIR, "sessions.json"), "w",
                  encoding="utf-8") as f:
            json.dump(sessions[:20], f)
    except Exception:
        pass

    print(
        f"\nMonitored {summary['total']} users "
        f"({summary['known']} known, {summary['new']} new) — "
        f"{summary['flagged']} flagged, {summary['safe']} clear."
    )


# ---------------------------------------------------------------------
# Evaluation + dashboard
# ---------------------------------------------------------------------

def evaluate():
    print("\n===== Evaluating ML Model =====")
    ModelEvaluator().evaluate()


def build_dashboard(open_browser=False, auto_refresh=None):
    import os
    from reporting.dashboard import DashboardBuilder
    path = DashboardBuilder().build(auto_refresh=auto_refresh)

    if open_browser:
        abspath = os.path.abspath(path)
        opened = False
        # os.startfile is the most reliable way to open a local file in
        # the default browser on Windows; fall back to webbrowser.
        try:
            os.startfile(abspath)  # noqa: S606 (Windows-only)
            opened = True
        except (AttributeError, OSError):
            pass
        if not opened:
            import webbrowser
            webbrowser.open("file://" + abspath)
        print(f"\nDashboard opened: {abspath}")

    return path
