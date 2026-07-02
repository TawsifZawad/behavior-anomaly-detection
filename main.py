import platform

from ml.trainer import BehaviorTrainer
from ml.predictor import BehaviorPredictor

from behavior_detection.decision_engine import DecisionEngine
from behavior_detection.risk_engine import RiskEngine
from behavior_detection.analyzer import BehaviorAnalyzer

from feature_engine.aggregator import EventAggregator
from feature_engine.extractor import FeatureExtractor
from feature_engine.baseline import BaselineManager
from feature_engine.comparator import BehaviorComparator
from feature_engine.dataset_generator import DatasetGenerator

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


# =====================================================
# Detect Operating System
# =====================================================

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


# =====================================================
# Initialize
# =====================================================

create_tables()

aggregator = EventAggregator()
extractor = FeatureExtractor()
baseline = BaselineManager()
comparator = BehaviorComparator()


# =====================================================
# BASELINE TRAINING
# =====================================================

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

baseline_groups = aggregator.group_by_user(
    baseline_event_objects
)

baseline_feature_vectors = []

print("\n===== Feature Extraction =====")

for username, events in baseline_groups.items():

    features = extractor.extract(events)

    baseline_feature_vectors.append(features)

    print(features)


print("\n===== Baseline Learning =====")

for features in baseline_feature_vectors:

    baseline.save(features)


# =====================================================
# BUILD ML DATASET
# =====================================================

print("\n===== Building ML Dataset =====")

generator = DatasetGenerator()

for features in baseline_feature_vectors:

    generator.generate(
        features,
        samples=200
    )

generator.save()


# =====================================================
# TRAIN ML MODEL
# =====================================================

print("\n===== Training ML Model =====")

trainer = BehaviorTrainer()

trainer.train()


# =====================================================
# CURRENT SESSION
# =====================================================

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

current_feature_vectors = []

print("\n===== Current Feature Extraction =====")

for username, events in current_groups.items():

    features = extractor.extract(events)

    current_feature_vectors.append(features)

    print(features)


# =====================================================
# BEHAVIOR COMPARISON
# =====================================================

print("\n===== Behavior Comparison =====")

predictor = BehaviorPredictor()
decision_engine = DecisionEngine()

for features in current_feature_vectors:

    user = baseline.load(features.username)

    if user is None:

        print(f"\nNo baseline found for {features.username}")

        continue

    comparison = comparator.compare(features, user)

    print(f"\n===== {features.username} =====")

    for feature, value in comparison.items():

        print(f"\n{feature}")

        print(value)

    # =====================================================
    # Risk Analysis
    # =====================================================

    print("\n===== Risk Analysis =====")

    risk_engine = RiskEngine()

    score, reasons = risk_engine.calculate(comparison)

    analyzer = BehaviorAnalyzer()

    level = analyzer.get_risk_level(score)

    print(f"Risk Score : {score}")

    print(f"Risk Level : {level}")

    print("\nReasons:")

    if reasons:

        for reason in reasons:

            print("-", reason)

    else:

        print("No abnormal behavior detected.")

    # =====================================================
    # ML Prediction
    # =====================================================

    print("\n===== ML Prediction =====")

    label, confidence = predictor.predict(features)

    print(f"Prediction : {label}")
    print(f"Confidence : {confidence:.2f}%")

    # =====================================================
    # Final Decision
    # =====================================================

    print("\n===== Final Decision =====")

    final_status = decision_engine.decide(
        score,
        label
    )

    print(f"Final Status : {final_status}")

    if final_status == "CRITICAL":

        print("Action : Immediate Investigation Required")

    elif final_status == "SUSPICIOUS":

        print("Action : Rule Engine detected suspicious behavior")

    elif final_status == "REVIEW":

        print("Action : Review recommended by ML model")

    elif final_status == "SAFE":

        print("Action : No action required")

    else:

        print("Action : Normal user")