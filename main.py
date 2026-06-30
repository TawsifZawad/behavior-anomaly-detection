import platform

from behavior_detection.risk_engine import RiskEngine
from behavior_detection.analyzer import BehaviorAnalyzer

from feature_engine.aggregator import EventAggregator
from feature_engine.comparator import BehaviorComparator
from feature_engine.baseline import BaselineManager
from feature_engine.extractor import FeatureExtractor

from core.event import Event

from config.settings import (
    MODE,
    BASELINE_EVENT_FILE,
    CURRENT_EVENT_FILE
)

from core.database import (
    create_tables,
    insert_event,
    get_all_events,
    clear_events
)

from utils.data_loader import load_sample_events

from collectors.windows_collector import WindowsCollector
from collectors.ubuntu_collector import UbuntuCollector
from collectors.mac_collector import MacCollector


# ============================================================
# Select Operating System Collector
# ============================================================

os_name = platform.system()

print(f"Detected OS: {os_name}")

if os_name == "Windows":
    collector = WindowsCollector()

elif os_name == "Linux":
    collector = UbuntuCollector()

elif os_name == "Darwin":
    collector = MacCollector()

else:
    raise Exception("Unsupported Operating System")


# ============================================================
# Create Database
# ============================================================

create_tables()


# ============================================================
# BASELINE TRAINING
# ============================================================

print("\n===== Baseline Training =====")

clear_events()

baseline_events = load_sample_events(BASELINE_EVENT_FILE)

for event in baseline_events:
    insert_event(event)

rows = get_all_events()

baseline_event_objects = []

for row in rows:

    baseline_event_objects.append(

        Event(
            timestamp=row[1],
            username=row[2],
            os=row[3],
            event_type=row[4],
            source=row[5],
            ip=row[6],
            details=row[7]
        )

    )

aggregator = EventAggregator()

baseline_groups = aggregator.group_by_user(baseline_event_objects)

extractor = FeatureExtractor()

baseline_manager = BaselineManager()

print("\n===== Baseline Feature Extraction =====")

for username, events in baseline_groups.items():

    features = extractor.extract(events)

    print(features)

    baseline_manager.save(features)


# ============================================================
# CURRENT SESSION
# ============================================================

print("\n===== Current Session =====")

clear_events()

if MODE == "development":

    current_events = load_sample_events(CURRENT_EVENT_FILE)

    for event in current_events:
        insert_event(event)

else:

    collector.collect()


rows = get_all_events()

current_event_objects = []

for row in rows:

    current_event_objects.append(

        Event(
            timestamp=row[1],
            username=row[2],
            os=row[3],
            event_type=row[4],
            source=row[5],
            ip=row[6],
            details=row[7]
        )

    )


current_groups = aggregator.group_by_user(current_event_objects)

print("\n===== Current Feature Extraction =====")

current_feature_vectors = []

for username, events in current_groups.items():

    features = extractor.extract(events)

    current_feature_vectors.append(features)

    print(features)


# ============================================================
# Behavior Comparison
# ============================================================

print("\n===== Behavior Comparison =====")

comparator = BehaviorComparator()

risk_engine = RiskEngine()

behavior_analyzer = BehaviorAnalyzer()

for features in current_feature_vectors:

    user = baseline_manager.load(features.username)

    if user is None:

        print(f"\nNo baseline found for {features.username}")

        continue

    comparison = comparator.compare(features, user)

    print(f"\n===== {features.username} =====")

    for feature, value in comparison.items():

        print(f"\n{feature}")

        print(value)

    print("\n===== Risk Analysis =====")

    score, reasons = risk_engine.calculate(comparison)

    level = behavior_analyzer.get_risk_level(score)

    print(f"Risk Score : {score}")

    print(f"Risk Level : {level}")

    print("\nReasons:")

    if reasons:

        for reason in reasons:
            print("-", reason)

    else:
        print("No abnormal behavior detected.")