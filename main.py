import platform

from feature_engine.aggregator import EventAggregator
from feature_engine.comparator import BehaviorComparator
from feature_engine.baseline import BaselineManager
from feature_engine.extractor import FeatureExtractor
from core.event import Event
from config.settings import MODE, SAMPLE_EVENT_FILE

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


os_name = platform.system()

print(f"Detected OS: {os_name}")


# Select Collector
if os_name == "Windows":
    collector = WindowsCollector()

elif os_name == "Linux":
    collector = UbuntuCollector()

elif os_name == "Darwin":
    collector = MacCollector()

else:
    raise Exception("Unsupported Operating System")


# Create Database
create_tables()


# Development / Production Mode
if MODE == "development":

    print("Running in Development Mode...")

    clear_events()

    events = load_sample_events(SAMPLE_EVENT_FILE)

    for event in events:
        insert_event(event)

else:

    print("Running in Production Mode...")

    collector.collect()


# Show Database Contents
events = get_all_events()

print("\n===== Events in Database =====")

for event in events:
    print(event)


print("\n===== Feature Extraction =====")

rows = get_all_events()

event_objects = []

for row in rows:

    event = Event(
        timestamp=row[1],
        username=row[2],
        os=row[3],
        event_type=row[4],
        source=row[5],
        ip=row[6],
        details=row[7]
    )

    event_objects.append(event)


aggregator = EventAggregator()

grouped_events = aggregator.group_by_user(event_objects)

extractor = FeatureExtractor()

feature_vectors = []

for username, events in grouped_events.items():

    features = extractor.extract(events)

    feature_vectors.append(features)

    print(features)


print("\n===== Baseline Learning =====")

baseline = BaselineManager()

for features in feature_vectors:

    baseline.save(features)


print("\n===== Behavior Comparison =====")

comparator = BehaviorComparator()

for features in feature_vectors:

    user = baseline.load(features.username)

    comparison = comparator.compare(features, user)

    print(f"\n===== {features.username} =====")

    for feature, value in comparison.items():

        print(f"\n{feature}")

        print(value)