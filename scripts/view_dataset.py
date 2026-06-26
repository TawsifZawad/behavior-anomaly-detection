import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
csv_path = BASE_DIR / "data" / "user_activity.csv"

data = pd.read_csv(csv_path)

print(data)