# Behavior Anomaly Detection System (bads)

Hybrid, cross-platform intrusion detection that fuses **rule-based
detection**, **multi-stage correlation**, and a **lightweight
Isolation-Forest behavioral anomaly model (UEBA)** — with **Suricata**
network telemetry and **Wazuh** SIEM alerts — and maps findings to
**MITRE ATT&CK**. Focused on rare **U2R / R2L** attacks.

PMICS thesis project, University of Dhaka.

## Quick start

```bash
pip install -r requirements.txt
python bads.py demo          # full end-to-end sample run + dashboard
```

Or run a packaged demo binary from `software/` (see `BUILD.md` and
`software/README.md`) — on Windows double-click `software\windows-demo.exe`
(or `Run-Demo.bat`); on Linux/macOS run `./software/linux-demo` /
`./software/macos-demo`. No argument shows a menu:

```
[1] Own      - scan THIS computer (needs Administrator)
[2] Analyze  - report on the stored sample data
[3] Live     - keep monitoring THIS computer
```

## Commands

| Command                     | What it does                               |
| --------------------------- | ------------------------------------------ |
| `python bads.py demo`       | learn → analyze sample (host+net+SIEM) → dashboard |
| `python bads.py own`        | scan the current machine (live)            |
| `python bads.py analyze`    | analyze the stored sample data             |
| `python bads.py watch`      | continuous live monitoring                 |
| `python bads.py learn`      | build baselines + train the model          |
| `python bads.py evaluate`   | metrics + confusion matrix + ROC           |
| `python bads.py benchmark`  | NSL-KDD Isolation-Forest benchmark         |
| `python bads.py dashboard`  | (re)build the HTML dashboard               |

Outputs: `reports/dashboard.html`, `reports/*.png`, `alerts/`.

## Detection layers

1. **Rules** (`specs/`, `core/process_detector.py`, `file_detector.py`,
   `network_detector.py`, `wazuh_detector.py`) — context-aware signatures
   (never process-name alone): command line, parent process, path, USB,
   signature, LOLBins, ransomware, credential access, reverse shells.
2. **Correlation** (`behavior_detection/correlation_engine.py`) —
   multi-stage + **cross-plane** chains (host + network + SIEM).
3. **Anomaly ML** (`ml/`) — Isolation Forest over **15 distinct
   standardized behavioral features** (timing, volume, intensity,
   variety, auth, device, network source) detecting novel deviations
   from each user's learned normal.

## Layout

```
bads.py                 CLI entry point
main.py                 back-compat shim -> `bads demo`
config/                 settings
core/                   pipeline, detectors, database, event, logger
collectors/             per-OS collectors + parsers (Windows/Ubuntu/macOS)
feature_engine/         aggregation, extraction, baseline, dataset build
behavior_detection/     risk, correlation, decision, alerts, analyzer
ml/                     trainer, predictor, evaluator, model.joblib
models/                 FeatureVector + ML feature lists
specs/                  rule specs + MITRE mappings
reporting/              dashboard + report generator
readers/                EVTX reader
scripts/                dataset/user generators, replay, benchmark
demo/                   sample users (100) for reproducible demo
data/                   datasets (EVTX, NSL-KDD), network/SIEM samples
reports/  alerts/  logs/  database/   runtime outputs
```
