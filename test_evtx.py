from readers.evtx_reader import EVTXReader

FILE_PATH = r"data/datasets/windows/EVTX-ATTACK-SAMPLES-master/PASTE_THE_REAL_PATH_HERE.evtx"

reader = EVTXReader(FILE_PATH)

events = reader.read_events()

print(f"Total Events : {len(events)}")

print("\n========== First Event ==========\n")

print(events[0])