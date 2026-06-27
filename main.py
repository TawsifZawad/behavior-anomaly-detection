import platform

from core.database import create_tables, get_all_events
from collectors.windows_collector import WindowsCollector
from collectors.ubuntu_collector import UbuntuCollector
from collectors.mac_collector import MacCollector


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

create_tables()

collector.collect()

events = get_all_events()

print("\n===== Events in Database =====")

for event in events:
    print(event)