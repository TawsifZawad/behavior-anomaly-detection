"""
Replay real EVTX attack samples through the detection pipeline.

For every .evtx file in the selected MITRE tactic folders of the
EVTX-ATTACK-SAMPLES dataset this script:

    1. reads records (readers/evtx_reader.py),
    2. maps Security 4688 / 4624 / 4625 and Sysmon Event ID 1 records to
       normalized Event objects,
    3. runs process command lines through the ProcessDetector to produce
       context-aware derived events,
    4. treats one file as one attack "session", extracts a FeatureVector,
    5. writes the vector to the evaluation set (data/ml_eval.csv, label=1),
    6. prints an end-to-end detection summary (risk, correlations,
       final decision) per file.

This gives the Isolation Forest an honest, real-attack evaluation set
that it never trained on, and demonstrates the rule/correlation engines
firing on genuine attack telemetry.

Usage:
    python -m scripts.replay_attack_samples
    python -m scripts.replay_attack_samples --tactics Execution "Privilege Escalation"
"""

import os
import csv
import sys
import argparse
import xml.etree.ElementTree as ET

# Allow running as `python scripts/replay_attack_samples.py`
sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from readers.evtx_reader import EVTXReader
from core.event import Event
from core.process_detector import ProcessDetector
from core.file_detector import FileDetector
from feature_engine.extractor import FeatureExtractor
from feature_engine.comparator import BehaviorComparator
from behavior_detection.risk_engine import RiskEngine
from behavior_detection.correlation_engine import CorrelationEngine
from behavior_detection.decision_engine import DecisionEngine
from behavior_detection.analyzer import BehaviorAnalyzer
from ml.predictor import BehaviorPredictor
from models.feature_vector import ML_FEATURES
from config.settings import ML_EVAL_FILE

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

FILE_DETECTOR = FileDetector()

DATASET_ROOT = os.path.join(
    "data", "datasets", "windows",
    "EVTX-ATTACK-SAMPLES-master"
)

DEFAULT_TACTICS = [
    "Execution",
    "Privilege Escalation",
    "Credential Access",
    "Lateral Movement",
    "Persistence",
]


def clean_timestamp(raw):
    """Normalize a Windows/Sysmon SystemTime into an ISO string."""
    if not raw:
        return None
    ts = raw.replace("Z", "")
    return ts


def event_data(root):
    data = {}
    for item in root.findall(".//e:EventData/e:Data", NS):
        data[item.attrib.get("Name")] = item.text
    return data


def map_record(xml, detector):
    """
    Convert one EVTX XML record into a base Event plus any derived
    context-aware events. Returns a list of Event objects (possibly
    empty for records we don't model).
    """
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []

    event_id_el = root.find(".//e:EventID", NS)
    if event_id_el is None:
        return []
    event_id = (event_id_el.text or "").strip()

    channel_el = root.find(".//e:Channel", NS)
    channel = channel_el.text if channel_el is not None else ""

    time_el = root.find(".//e:TimeCreated", NS)
    timestamp = clean_timestamp(
        time_el.attrib.get("SystemTime") if time_el is not None else None
    )

    rec_el = root.find(".//e:EventRecordID", NS)
    record_id = rec_el.text if rec_el is not None else None

    data = event_data(root)
    events = []

    # ---- File creation (Sysmon Event ID 11) -----------------------
    if event_id == "11" and "Sysmon" in (channel or ""):
        target = data.get("TargetFilename", "")
        image = data.get("Image", "")
        user = data.get("User", "attacker")
        if user and "\\" in user:
            user = user.split("\\")[-1]

        result = FILE_DETECTOR.analyze(target, image)
        if result:
            for i, derived_type in enumerate(result["derived_events"]):
                events.append(Event(
                    timestamp=timestamp,
                    username=user or "attacker",
                    os="Windows",
                    event_type=derived_type,
                    source="FileDetector",
                    ip="-",
                    details=f"{result['target']} | {image}",
                    event_record_id=f"{record_id}-{i}-{derived_type}",
                ))
        return events

    # ---- Login events (Security 4624 / 4625) ----------------------
    if event_id in ("4624", "4625"):
        events.append(Event(
            timestamp=timestamp,
            username=data.get("TargetUserName", "attacker"),
            os="Windows",
            event_type="LOGIN_SUCCESS" if event_id == "4624" else "LOGIN_FAILED",
            source="Security",
            ip=data.get("IpAddress", "-"),
            details=str(data),
            event_record_id=record_id,
        ))
        return events

    # ---- Process creation: Security 4688 or Sysmon 1 --------------
    image = None
    command = None
    user = None
    parent = None

    if event_id == "4688":
        image = data.get("NewProcessName", "")
        command = data.get("CommandLine", "") or image
        user = data.get("SubjectUserName") or data.get("TargetUserName")
        parent = data.get("ParentProcessName", "")
    elif event_id == "1" and "Sysmon" in (channel or ""):
        image = data.get("Image", "")
        command = data.get("CommandLine", "") or image
        user = data.get("User", "")
        parent = data.get("ParentImage", "")

    if image is None:
        return []

    # Sysmon "DOMAIN\\user" -> user
    if user and "\\" in user:
        user = user.split("\\")[-1]
    user = user or "attacker"

    base = Event(
        timestamp=timestamp,
        username=user,
        os="Windows",
        event_type="PROCESS_START",
        source=channel or "Security",
        ip="-",
        details=f"{image} | {command}",
        event_record_id=record_id,
    )
    events.append(base)

    result = detector.analyze(image, command, parent_process=parent)
    if result:
        for i, derived_type in enumerate(result["derived_events"]):
            events.append(Event(
                timestamp=timestamp,
                username=user,
                os="Windows",
                event_type=derived_type,
                source="ProcessDetector",
                ip="-",
                details=f"{os.path.basename(image)} | {command}",
                event_record_id=f"{record_id}-{i}-{derived_type}",
            ))

    return events


def process_file(path, detector, extractor):
    """Return (FeatureVector, event_count) for one EVTX file, or (None, 0)."""
    try:
        records = EVTXReader(path).read_events()
    except Exception as exc:  # noqa: BLE001 - report and skip bad files
        print(f"  ! could not read: {exc}")
        return None, 0

    events = []
    for xml in records:
        events.extend(map_record(xml, detector))

    if not events:
        return None, 0

    # One file = one attack session. Force a single username so the
    # per-user extractor aggregates the whole file together.
    session_user = os.path.splitext(os.path.basename(path))[0][:40]
    for ev in events:
        ev.username = session_user

    features = extractor.extract(events)
    return features, len(events)


def write_eval_rows(rows):
    """
    Rebuild the evaluation set: keep any existing NORMAL rows (label 0,
    e.g. held-out normals from the bootstrap generator), drop previous
    ATTACK rows, and write the fresh real-attack rows. This keeps the
    eval set honest and idempotent across repeated replay runs.
    """
    os.makedirs(os.path.dirname(ML_EVAL_FILE), exist_ok=True)
    header = ["username"] + ML_FEATURES + ["label"]

    normal_rows = []
    if os.path.exists(ML_EVAL_FILE):
        with open(ML_EVAL_FILE, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            existing_header = next(reader, None)
            # Keep old normals only if the feature schema is unchanged;
            # otherwise their columns no longer line up with the header.
            if existing_header == header:
                for row in reader:
                    if row and row[-1] == "0":
                        normal_rows.append(row)

    with open(ML_EVAL_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(normal_rows)
        writer.writerows(rows)


def feature_row(features):
    return (
        [features.username]
        + [getattr(features, name) for name in ML_FEATURES]
        + [1]
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tactics", nargs="+", default=DEFAULT_TACTICS)
    parser.add_argument("--limit", type=int, default=0,
                        help="max files per tactic (0 = all)")
    args = parser.parse_args()

    detector = ProcessDetector()
    extractor = FeatureExtractor()
    comparator = BehaviorComparator()
    risk_engine = RiskEngine()
    correlation_engine = CorrelationEngine()
    decision_engine = DecisionEngine()
    analyzer = BehaviorAnalyzer()

    # Use the real trained model for the ML verdict when available, so the
    # printed decisions and detection rate are honest. Falls back to a
    # rules-only verdict if no model has been trained yet.
    try:
        predictor = BehaviorPredictor()
    except FileNotFoundError:
        predictor = None
        print("[warn] No trained model found; ML verdict skipped "
              "(run main.py first). Using rules-only decisions.")

    eval_rows = []
    detected = 0
    total = 0

    for tactic in args.tactics:

        folder = os.path.join(DATASET_ROOT, tactic)
        if not os.path.isdir(folder):
            print(f"[skip] tactic folder not found: {folder}")
            continue

        print(f"\n========== {tactic} ==========")

        files = sorted(
            f for f in os.listdir(folder) if f.lower().endswith(".evtx")
        )
        if args.limit:
            files = files[: args.limit]

        for name in files:

            path = os.path.join(folder, name)
            features, count = process_file(path, detector, extractor)

            if features is None:
                continue

            total += 1
            eval_rows.append(feature_row(features))

            # Detection summary (no baseline -> empty comparison, so the
            # score is driven entirely by context-aware threat rules).
            score, reasons = risk_engine.calculate({}, features)
            correlations = correlation_engine.analyze({}, features)
            level = analyzer.get_risk_level(score)

            if predictor is not None:
                ml_label, _ = predictor.predict(features)
            else:
                ml_label = "NORMAL"

            decision = decision_engine.decide(score, ml_label, correlations)

            # Any non-benign verdict on a known-attack file counts as a
            # detection (REVIEW = ML flagged it; SUSPICIOUS/CRITICAL =
            # rules/correlation flagged it).
            if decision not in ("SAFE", "NORMAL"):
                detected += 1

            print(f"\n[{name}]  events={count}")
            print(f"  risk={score} ({level})  ml={ml_label}  decision={decision}")
            if correlations:
                for c in correlations:
                    print(
                        f"  chain: {c['name']} "
                        f"[{c['attack_class']}] {c['severity']} "
                        f"{','.join(c['mitre'])}"
                    )
            if reasons:
                print("  reasons: " + "; ".join(sorted(set(reasons))))

    if eval_rows:
        write_eval_rows(eval_rows)

    print("\n========== Summary ==========")
    print(f"Files processed : {total}")
    print(f"Flagged         : {detected}")
    if total:
        print(f"Detection rate  : {detected / total * 100:.1f}%")
    print(f"Eval rows written to {ML_EVAL_FILE}: {len(eval_rows)}")


if __name__ == "__main__":
    main()
