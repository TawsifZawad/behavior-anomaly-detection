"""
Final project report content (rendered by generate_report.py).
Blocks are (kind, text) pairs. All figures are taken from the project's
own verified runs and are reproducible with the stated commands.
"""

TITLE = ("Hybrid SIEM-Based Intrusion Detection with Lightweight "
         "Anomaly Detection for U2R and R2L Attacks")

BLOCKS = []


def h1(t): BLOCKS.append(("h1", t))
def h2(t): BLOCKS.append(("h2", t))
def h3(t): BLOCKS.append(("h3", t))
def p(t): BLOCKS.append(("p", t))
def b(t): BLOCKS.append(("b", t))
def ref(t): BLOCKS.append(("ref", t))
def note(t): BLOCKS.append(("note", t))
def code(t): BLOCKS.append(("code", t))
def table(r): BLOCKS.append(("table", r))
def table3(r): BLOCKS.append(("table3", r))
def space(x=8): BLOCKS.append(("space", x))
def img(path, caption, width_cm=15.5): BLOCKS.append(("image", (path, caption, width_cm)))


# ===================================================================
# ABSTRACT
# ===================================================================
h1("Abstract")
p("Traditional Intrusion Detection Systems (IDS) and Security Information "
  "and Event Management (SIEM) platforms rely mainly on rule- and "
  "signature-based detection. They are effective against known threats "
  "but struggle with rare, stealthy attacks such as User-to-Root (U2R) "
  "and Remote-to-Local (R2L) intrusions, which resemble ordinary activity "
  "and produce high false-negative rates.")
p("This project presents a hybrid, cross-platform intrusion-detection "
  "system that combines three complementary layers — context-aware "
  "rule-based detection, multi-stage correlation, and a lightweight "
  "unsupervised anomaly model (Isolation Forest) — over three independent "
  "data planes: host telemetry (Windows, Ubuntu, macOS), network "
  "telemetry (Suricata), and SIEM alerts (Wazuh). Findings are mapped to "
  "the MITRE ATT&amp;CK framework, and the distinctive contribution is "
  "cross-plane correlation, in which a host observation confirmed by an "
  "independent network or SIEM observation yields a high-confidence "
  "verdict that neither plane could reach alone.")
p("The system was validated three ways. On a reproducible 100-user "
  "scenario it correctly cleared 96 ordinary users, raised one critical "
  "multi-stage attack, and flagged three new users for review. Against "
  "137 real, publicly published Windows attack recordings it achieved a "
  "98.5% detection rate. On the standard NSL-KDD benchmark the anomaly "
  "model reached a ROC area of 0.944; crucially, its per-category results "
  "confirm the project's premise — network-flow anomaly detection alone "
  "is weak on the rare U2R (73.1%) and R2L (44.9%) classes, which is "
  "precisely why the added host, SIEM and correlation layers are "
  "necessary. The system is packaged as a single cross-platform "
  "application with an operator-tunable allowlist and an explainable "
  "dashboard, keeping computational cost low while reducing false alarms.")


# ===================================================================
# 1. INTRODUCTION
# ===================================================================
h1("1. Introduction")

h2("1.1 Background")
p("Modern organisations depend on SIEM and IDS tooling to monitor their "
  "systems. These tools excel at recognising known attack signatures, but "
  "low-frequency, stealthy intrusions — particularly U2R (a normal user "
  "escalating to administrator) and R2L (an outsider gaining local access "
  "with stolen or guessed credentials) — exploit systems in subtle ways "
  "that static rules miss. Because such attacks are rare and blend into "
  "normal activity, purely signature-based mechanisms produce high "
  "false-negative rates for exactly the classes that matter most.")

h2("1.2 Problem Statement")
p("Existing IDS/SIEM deployments exhibit four recurring limitations:")
b("They depend mostly on predefined rules and static signatures.")
b("They fail to detect unknown or rare attack patterns (U2R, R2L).")
b("They produce high false-negative rates for low-frequency attack classes.")
b("They lack adaptive learning for an evolving threat landscape.")

h2("1.3 Research Objectives")
b("Design a hybrid detection system combining SIEM/rule-based detection "
  "with anomaly detection.")
b("Improve detection of rare U2R and R2L attacks.")
b("Evaluate performance using both real logs and a benchmark dataset.")
b("Map detected behaviour to MITRE ATT&amp;CK techniques.")

h2("1.4 Scope")
p("The delivered system covers: a cross-platform host-simulation and "
  "collection environment (Windows, Ubuntu, macOS); SIEM integration via "
  "Wazuh alerts; network monitoring via Suricata; lightweight anomaly "
  "detection using Isolation Forest; validation on real attack recordings "
  "and the NSL-KDD benchmark; and MITRE ATT&amp;CK mapping throughout.")
note("The original proposal targeted a Linux-only environment. The "
     "implemented system generalises to Windows, Ubuntu and macOS with a "
     "single shared detection pipeline; the Linux focus of U2R/R2L "
     "detection is retained and extended.")

h2("1.5 Contributions")
b("A context-aware detection design that never classifies a process by "
  "name alone, using command line, parent process, execution path, "
  "digital signature and file naming.")
b("A tri-plane architecture (host + network + SIEM) with cross-plane "
  "correlation as the core novelty.")
b("A behavioural anomaly model over fifteen distinct, standardized "
  "features with a self-explaining, per-feature deviation output.")
b("An operator-tunable allowlist that suppresses the tool's own and "
  "known-good activity, lowering false positives without weakening "
  "detection.")
b("A single, self-locating cross-platform application with an "
  "explainable dashboard and reproducible benchmarks.")


# ===================================================================
# 2. LITERATURE REVIEW
# ===================================================================
h1("2. Literature Review")
p("Six closely related systems informed this design. Each is examined "
  "for method, dataset, performance and — most importantly — its limits "
  "on rare U2R/R2L classes.")

h2("2.1 Wazuh with Machine-Learning Enhancement")
p("Chamkar et al. (2025) augmented Wazuh with Random Forest and DBSCAN to "
  "cut its high false-positive rate. RF reached 97.2% accuracy and DBSCAN "
  "91.06% with sub-100 ms latency, but U2R and R2L were not evaluated and "
  "testing used a controlled enterprise simulation. This gap directly "
  "motivates the present project. [1]")

h2("2.2 Hybrid Ensemble IDS on NSL-KDD")
p("Mills et al. (2024) used a supervised stacking ensemble, reaching "
  "99.84% accuracy on NSL-KDD. Yet U2R detection remained at only 62.5% "
  "F1 due to severe class imbalance, underscoring the persistent "
  "difficulty of U2R even for strong supervised models — and the case for "
  "a complementary unsupervised layer. [2]")

h2("2.3 Isolation Forest for Anomaly Detection")
p("Bello et al. (2024) applied Isolation Forest to NSL-KDD, obtaining "
  "95.2% accuracy at a 4.7% false-positive rate and outperforming "
  "One-Class SVM and Local Outlier Factor, with sub-linear time "
  "complexity and no need for labelled data. This directly supports the "
  "choice of Isolation Forest as the anomaly layer here. [3]")

h2("2.4 Suricata vs. Snort")
p("Shah and Issac (2018), confirmed by a 2024 benchmark, found Suricata "
  "highly scalable (multi-threaded) with competitive precision/recall, "
  "but — like Snort — entirely signature-based and unable to detect "
  "zero-day behaviour. This is exactly the gap the anomaly layer fills "
  "on top of Suricata's network view. [4][5]")

h2("2.5 MITRE ATT&CK-Aligned SIEM Evaluation")
p("Winkler and Sharma (2025) evaluated Wazuh against Atomic Red Team, "
  "reporting ~85% overall detection with strong Command-and-Control and "
  "Impact coverage but partial Collection/Exfiltration due to "
  "telemetry-correlation gaps — motivating both ATT&amp;CK mapping and "
  "richer correlation. [6]")

h2("2.6 Hybrid K-Means + CNN/LSTM")
p("Lv and Ding (2024) combined K-Means with a CNN+LSTM deep model on "
  "NSL-KDD, achieving strong DoS/Probe results but requiring GPU-scale "
  "resources and labelled data — impractical for lightweight deployment. "
  "This project deliberately selects the far lighter Isolation Forest for "
  "comparable anomaly detection on standard hardware. [7]")

h2("2.7 Research Gap")
p("Across the literature a consistent gap appears: systems either achieve "
  "high overall accuracy through supervised learning yet fail on rare U2R "
  "(as low as 62.5% F1), or provide real-time SIEM/IDS capability but "
  "lack adaptive anomaly detection for unknown behaviour. No prior work "
  "simultaneously integrates Wazuh SIEM, Suricata network monitoring, "
  "Isolation Forest anomaly detection and MITRE ATT&amp;CK mapping in a "
  "single, resource-efficient, cross-platform framework aimed at U2R and "
  "R2L. This project addresses all four dimensions together.")
table3([
    ["System", "Accuracy / note", "U2R handling"],
    ["Wazuh rule-based [1]", "~78%", "Limited"],
    ["Ensemble stacking [2]", "99.84%", "62.5% F1"],
    ["Isolation Forest [3]", "95.2%", "Good (unsupervised)"],
    ["Suricata NIDS [4,5]", "~87%", "None (signature only)"],
    ["Wazuh + ATT&CK [6]", "~85%", "Not evaluated"],
    ["CNN+LSTM hybrid [7]", "~93%", "Moderate (heavy)"],
    ["This project", "see Section 6", "Primary goal"],
])


# ===================================================================
# 3. PROPOSED SYSTEM ARCHITECTURE
# ===================================================================
h1("3. Proposed System Architecture")

h2("3.1 Design Principle")
p("The central rule is that a process is never judged malicious by its "
  "executable name alone. Running PowerShell is not an attack; running "
  "PowerShell with a hidden, base64-encoded command that downloads and "
  "executes remote code is. Every decision therefore considers context — "
  "the full command line, the parent process, the execution path, the "
  "digital signature, the file name, and surrounding activity. This "
  "mirrors modern EDR practice and is the primary reason the "
  "false-positive rate stays low.")

h2("3.2 Processing Pipeline")
p("A single pipeline underlies every operating mode, so the logic exists "
  "exactly once:")
code("Collect -> Normalise -> Detect (add meaning) -> Extract features\n"
     "        -> Judge (rules + correlation + ML) -> Decide -> Report")
b("<b>Collect</b> — an OS/plane-specific collector fetches raw records.")
b("<b>Normalise</b> — a parser converts each record to one common Event "
  "object, after which the system is OS-independent.")
b("<b>Detect</b> — detectors add context-aware meaning (e.g. "
  "ENCODED_COMMAND, USB_EXECUTABLE_RUN) with MITRE codes, keeping the "
  "raw evidence.")
b("<b>Extract</b> — the feature engine reduces a user's session to a "
  "fixed numeric feature vector.")
b("<b>Judge</b> — three independent engines score the vector.")
b("<b>Decide</b> — the decision engine fuses the three into one verdict.")
b("<b>Report</b> — the alert manager records evidence-rich alerts; the "
  "dashboard renders them.")
img("docs/img/architecture.png",
    "Figure 1. System architecture: three data planes feed one "
    "OS-independent pipeline, judged by three engines and fused into a "
    "single explainable verdict.", 13.5)

h2("3.3 The Three Detection Layers")
table([
    ["Layer", "Role"],
    ["Rule-based (context-aware)",
     "Recognises known-bad patterns in commands, paths, files and network "
     "/ SIEM alerts. Precise and explainable; limited to known techniques."],
    ["Correlation",
     "Joins several weak signals into a named, MITRE-tagged attack chain, "
     "raising confidence to a CRITICAL verdict."],
    ["Anomaly (Isolation Forest)",
     "Learns each machine's normal behaviour and flags statistically "
     "significant deviation. Catches novel/rare activity but does not name "
     "the threat."],
])

h2("3.4 The Three Data Planes and Cross-Plane Correlation")
p("The system fuses three independent viewpoints. The host plane is read "
  "by the project's own collectors; the network plane is read from "
  "Suricata's eve.json; the SIEM plane is read from Wazuh's alerts.json. "
  "Suricata and Wazuh are consumed as data sources — the system reads the "
  "reports they produce, it does not launch them.")
p("Cross-plane correlation is the distinctive contribution: a finding "
  "confirmed by two independent planes is far stronger than either alone.")
table([
    ["Host signal + independent plane", "Confirmed verdict"],
    ["Encoded command + malicious-host contact (network)",
     "Confirmed Command-and-Control channel"],
    ["Failed logins + port scan (network)",
     "Confirmed scan-then-brute-force (R2L)"],
    ["Credential access + large outbound transfer (network)",
     "Confirmed exfiltration after access"],
    ["Suspicious download + malicious source IP (network)",
     "Confirmed malicious delivery"],
    ["Any behavioural threat + Wazuh alert (SIEM)",
     "Hybrid SIEM + behavioural confirmation"],
])


# ===================================================================
# 4. IMPLEMENTATION
# ===================================================================
h1("4. Implementation")
p("The system is implemented in Python (~8,500 lines across 60+ modules) "
  "and organised by responsibility. The following summarises each "
  "subsystem; a separate companion document explains every file in "
  "plain language.")

h2("4.1 Collectors (Host, Network, SIEM)")
b("<b>Windows</b> — reads the Security event log (logins 4624/4625, "
  "process creation 4688 with full command line and parent, file access "
  "4663), optional Sysmon file-creation, live USB drive detection and a "
  "time-boxed USB insertion monitor. Each phase is fault-tolerant: a "
  "permissions failure prints a clear message and the scan continues.")
b("<b>Ubuntu</b> — incrementally reads /var/log/auth.log (SSH accept/"
  "fail, sessions, sudo commands) and, when present, auditd EXECVE and "
  "file-creation records.")
b("<b>macOS</b> — reads the unified log (live) or a sample export, "
  "feeding the same detectors so macOS-specific techniques (AppleScript "
  "shells, /Volumes execution, launchctl persistence) are caught.")
b("<b>Suricata / Wazuh</b> — incremental JSON readers for eve.json and "
  "alerts.json, mapping network and SIEM events into the common Event "
  "shape.")

h2("4.2 Context-Aware Detectors")
b("<b>ProcessDetector</b> applies the allowlist, then keyword rule "
  "groups, temp/download path heuristics, USB-execution detection, "
  "double-extension masquerading, and office-parent phishing chains; a "
  "bare interpreter launch is a low-severity 'concern', not an accusation.")
b("<b>FileDetector</b> flags executables/scripts dropped into download, "
  "temp, desktop or removable locations.")
b("<b>NetworkDetector / WazuhDetector</b> translate Suricata and Wazuh "
  "categories into the project's meanings; the Wazuh reader reuses "
  "Wazuh's own MITRE mapping and reinforces matching host signals.")
b("<b>SignatureChecker</b> verifies Authenticode signatures, but only "
  "for already-suspicious executables, and never assumes 'unsigned' when "
  "the result is undeterminable.")

h2("4.3 Feature Engine and Anomaly Model")
p("The extractor produces a fixed feature vector; the model uses fifteen "
  "distinct behavioural features, each answering a different question — "
  "login and logout time, session length, off-hours share, weekend "
  "activity, activity intensity, activity spread, program volume, file "
  "volume, program variety, file-to-process balance, login failures, "
  "login attempts, USB use, and number of distinct network sources.")
p("Training (ml/trainer.py) standardizes the features — so low-magnitude "
  "threat indicators are not drowned by high-magnitude counts — and fits "
  "a 300-tree Isolation Forest on normal-only data. Two separate models "
  "are maintained: a sample model for reproducible analysis and a "
  "machine-specific model learned live, so live learning can never "
  "degrade the reproducible detection.")
p("Prediction returns an anomaly label, a 0–100 anomaly score (50 is the "
  "boundary), and a per-feature explanation computed from the model's own "
  "learned mean and standard deviation. For example, an attacker logging "
  "in at 02:00 against a learned norm of 08:36 (spread ~1.1 h) is "
  "reported as roughly six standard deviations away — a statistically "
  "near-impossible deviation, expressed in the model's own terms.")

h2("4.4 Risk, Correlation, Decision, Reporting")
b("The risk engine scores in two tiers — small weights for baseline "
  "deviation, large weights for genuinely dangerous context.")
b("The correlation engine forms named host and cross-plane chains.")
b("The decision engine fuses the three opinions: a critical chain wins "
  "outright; high risk with an anomaly is CRITICAL; an anomaly alone "
  "prompts human REVIEW.")
b("The alert manager records verdict, reasons, MITRE codes, anomaly "
  "score, deviating behaviours and the actual offending commands and file "
  "names. The dashboard presents every scanned session with an anomaly "
  "meter and, prominently, which behaviours deviated.")

h2("4.5 Baseline Comparison (UEBA)")
p("Each session is also compared to the user's own learned baseline. For "
  "high-volume features the tolerance is proportional to the baseline "
  "rather than a fixed constant, which is what makes per-user deviation "
  "usable on real machines where activity volume varies widely between "
  "sessions.")

h2("4.6 Allowlisting and False-Positive Control")
p("An operator-tunable allowlist suppresses trusted activity before "
  "classification, seeded with the tool's own operations so the monitor "
  "never alerts on itself. The same technique used by anything not on the "
  "list is still fully detected — the allowlist lowers false alarms "
  "without weakening detection.")

h2("4.7 Application and Packaging")
p("A single command-line application (bads.py) drives all modes — learn, "
  "detect/own, analyze, watch (live), evaluate, benchmark, dashboard — "
  "and self-locates its project folder so it runs from anywhere. It is "
  "packaged as software/windows-demo.exe (standalone) and, via a build "
  "script run on the target OS, as native Linux and macOS binaries; "
  "double-click launch presents an Own / Analyze / Live menu.")


# ===================================================================
# 5. DATASETS AND EXPERIMENTAL SETUP
# ===================================================================
h1("5. Datasets and Experimental Setup")
b("<b>Reproducible 100-user scenario</b> — 97 users with individual, "
  "self-consistent normal profiles; 3 brand-new users with no history; "
  "and one user given a full multi-stage attack aligned with the sample "
  "network and SIEM reports.")
b("<b>Sample network / SIEM / macOS telemetry</b> — representative "
  "Suricata (SSH scan, Cobalt Strike beacon, malicious domain, 50 MB "
  "exfiltration), Wazuh (brute force, privilege escalation, rootkit) and "
  "macOS attack traces.")
b("<b>Real attack recordings</b> — 137 published Windows EVTX attack "
  "samples spanning Execution, Privilege Escalation, Credential Access, "
  "Lateral Movement and Persistence, replayed through the full pipeline. "
  "The model never trains on these.")
b("<b>NSL-KDD</b> — the standard public intrusion-detection benchmark, "
  "used to evaluate the anomaly method against the literature.")
p("All results below are produced by the software itself and are "
  "reproducible with the stated commands.")


# ===================================================================
# 6. RESULTS AND EVALUATION
# ===================================================================
h1("6. Results and Evaluation")

h2("6.1 Reproducible 100-User Scenario")
p("Command: <i>analyze</i>. The system output:")
code("Monitored 100 users (97 known, 3 new) - 4 flagged, 96 clear")
b("<b>96 clear</b> — ordinary users, each judged against their own "
  "learned habits, correctly left alone (no false alarms).")
b("<b>1 CRITICAL</b> — the multi-stage attack: a 02:00 USB insertion, a "
  "disguised program (invoice.pdf.exe) run from it, an encoded PowerShell "
  "command, a payload in Downloads and credential theft on the host; an "
  "SSH scan, a Cobalt Strike beacon to a malicious server and a 50 MB "
  "upload on the network; and a Wazuh SIEM alert. Eleven correlation "
  "chains fired, including all four cross-plane chains.")
b("<b>3 REVIEW</b> — the new users with no baseline yet: the system "
  "states this honestly rather than guessing.")
p("A representative behavioural explanation from the dashboard for the "
  "attacker, generated from the model's own learned distribution:")
code("login time  2.0  vs usual 8.6   (about -6 SD)\n"
     "activity rate  high vs usual   (well above normal)\n"
     "off-hours activity  up;  weekend activity  up")
img("docs/img/dashboard.png",
    "Figure 2. The dashboard's behavioural-anomaly panel (real output). "
    "Each session shows an anomaly meter and exactly which behaviours "
    "deviated, in standard deviations from that user's learned normal — "
    "the model explaining its own reasoning.", 15.5)

h2("6.2 Real Attack Recordings (EVTX Replay)")
p("Command: <i>replay_attack_samples</i>. Of 137 real published Windows "
  "attack recordings, <b>135 were flagged — a 98.5% detection rate</b>. "
  "The two misses contain almost no evidence of the kind the system "
  "measures (one and three events, no command lines) — an acknowledged, "
  "not hidden, limitation. Because the model never trained on this data, "
  "this is the system's most trustworthy real-world figure.")

h2("6.3 NSL-KDD Benchmark")
p("Command: <i>benchmark</i>. The same Isolation Forest method, "
  "standardized and trained on normal traffic only, evaluated on the "
  "KDDTest+ set:")
table([
    ["Metric", "Result"],
    ["ROC area (threshold-independent)", "0.944"],
    ["Accuracy", "0.848"],
    ["Precision / Recall / F1", "0.895 / 0.830 / 0.861"],
    ["DoS detection", "92.4%"],
    ["Probe detection", "99.9%"],
    ["R2L detection", "44.9%"],
    ["U2R detection", "73.1%"],
])
img("reports/nsl_kdd/roc_curve.png",
    "Figure 3. ROC curve of the Isolation Forest on the NSL-KDD KDDTest+ "
    "set (area 0.944). The curve is a real, threshold-independent measure "
    "of how well the model separates attack from normal traffic.", 11.5)
p("This result is itself an argument for the whole design. Unsupervised "
  "network-flow anomaly detection is excellent on noisy attacks (DoS, "
  "Probe) but weak on exactly the rare classes this thesis targets, "
  "because at the network-flow level R2L and U2R closely resemble normal "
  "traffic. The ROC area of 0.944 is consistent with the literature "
  "(Bello et al. [3]) and confirms the algorithm choice; the weak "
  "per-category R2L/U2R figures are precisely why the system adds host "
  "behaviour, SIEM alerts and cross-plane correlation on top.")

h2("6.4 Held-out Model Evaluation")
p("On the project's own held-out evaluation set the model scores very "
  "highly (F1 near 1.0). This is stated plainly for honesty: those "
  "samples contain clean, unambiguous signals, so the figure should not "
  "be read as a real-world claim. The trustworthy figures are the 98.5% "
  "on real recordings (Section 6.2) and the 0.944 ROC area on the public "
  "benchmark (Section 6.3).")

h2("6.5 Objectives Revisited")
table([
    ["Objective", "Outcome"],
    ["Hybrid SIEM + anomaly detection",
     "Achieved — rules + correlation + Isolation Forest over host, "
     "Suricata and Wazuh planes."],
    ["Improve U2R / R2L detection",
     "Addressed — cross-plane and host layers cover the classes where "
     "network-flow anomaly detection is weak (benchmark 6.3)."],
    ["Evaluate on real logs and a benchmark",
     "Achieved — 98.5% on real EVTX recordings and NSL-KDD (0.944 ROC)."],
    ["Map to MITRE ATT&CK",
     "Achieved — every rule and correlation carries a technique code."],
])


# ===================================================================
# 7. DISCUSSION
# ===================================================================
h1("7. Discussion")

h2("7.1 How the Research Gap Is Closed")
p("The four elements the literature never combined — Wazuh SIEM, Suricata "
  "network monitoring, Isolation Forest and MITRE ATT&amp;CK mapping — are "
  "integrated in one lightweight, cross-platform framework, with "
  "cross-plane correlation binding them. Where supervised ensembles fail "
  "on rare U2R (Section 2.2) and pure network anomaly detection fails on "
  "R2L/U2R (Section 6.3), the layered, multi-plane approach provides "
  "complementary coverage and, unlike a black-box classifier, explains "
  "every verdict.")

h2("7.2 Strengths")
b("Context-aware detection and an operator allowlist keep false alarms "
  "low without weakening detection.")
b("Explainability at every step — MITRE codes, the offending commands, "
  "and per-feature behavioural deviations expressed in standard "
  "deviations.")
b("Low computational cost (Isolation Forest, no GPU, no labelled data), "
  "suitable for standard hardware, per the tradeoff observed in [7].")
b("A single cross-platform application with reproducible benchmarks.")

h2("7.3 Limitations and Honest Notes")
b("In the demonstration, Suricata and Wazuh are supplied via sample "
  "report files; a live deployment requires those services running and "
  "the two configured paths pointed at their output.")
b("Live host collection requires elevated privileges (Administrator on "
  "Windows, root on Linux/macOS) and, for full Windows process telemetry, "
  "process-creation auditing (and optionally Sysmon).")
b("The held-out model score is near-perfect because those samples are "
  "clean; the honest figures are the real-recording and benchmark "
  "results.")
b("Two of 137 real recordings were missed because they contain almost no "
  "measurable evidence.")
b("Native standalone binaries must be built on each target OS, as the "
  "packaging tool cannot cross-compile.")


# ===================================================================
# 8. CONCLUSION AND FUTURE WORK
# ===================================================================
h1("8. Conclusion and Future Work")
p("This project delivers a working, hybrid, cross-platform intrusion "
  "detection system that fuses context-aware rules, multi-stage "
  "correlation and lightweight anomaly detection across host, network and "
  "SIEM planes, with MITRE ATT&amp;CK mapping and an explainable "
  "dashboard. It targets the rare U2R and R2L classes that defeat "
  "conventional tools, and validates its approach on a reproducible "
  "scenario (correctly clearing 96 of 100 users while catching a "
  "multi-stage attack), on 137 real attack recordings (98.5% detection), "
  "and on the NSL-KDD benchmark (0.944 ROC), whose per-category weakness "
  "on R2L/U2R empirically justifies the multi-layer design.")
p("Future work includes: live integration and testing against running "
  "Suricata and Wazuh deployments; accumulating real normal history to "
  "further reduce borderline reviews; a richer network-anomaly channel "
  "(beaconing, DNS tunnelling); and an optional review queue in the "
  "dashboard for anomaly-only (REVIEW) findings.")


# ===================================================================
# REFERENCES
# ===================================================================
h1("References")
ref("[1] S. A. Chamkar, M. Zaydi, Y. Maleh, and N. Gherabi, \"Improving "
    "Threat Detection in Wazuh Using Machine Learning Techniques,\" J. "
    "Cybersecur. Priv., vol. 5, no. 2, p. 34, 2025.")
ref("[2] G. A. Mills, D. K. Acquah, and R. A. Sowah, \"Network Intrusion "
    "Detection and Prevention System Using Hybrid Machine Learning with "
    "Supervised Ensemble Stacking Model,\" J. Computer Networks and "
    "Communications, vol. 2024, p. 5775671, 2024.")
ref("[3] I. Bello, O. Adeyemi, and A. Okafor, \"Automation in "
    "Cybersecurity Using Machine Learning: A Case Study on Anomaly "
    "Detection with Isolation Forest,\" J. Technology Informatics and "
    "Engineering, vol. 4, no. 3, pp. 613–624, 2025.")
ref("[4] S. A. R. Shah and B. Issac, \"Performance Comparison of "
    "Intrusion Detection Systems and Application of Machine Learning to "
    "Snort System,\" Future Generation Computer Systems, vol. 80, pp. "
    "157–170, 2018.")
ref("[5] D. S. Ghazi, H. S. Hamid, M. J. Zaiter, and A. S. G. Behadili, "
    "\"Performance and Efficacy of Snort Versus Suricata in Intrusion "
    "Detection: A Benchmark Analysis,\" AIP Conf. Proc., vol. 3232, no. 1, "
    "p. 020024, 2024.")
ref("[6] A. M. Winkler and P. Sharma, \"Proactive Threat Detection in "
    "Enterprise Systems Using Wazuh: A MITRE ATT&amp;CK Evaluation,\" "
    "Computers &amp; Security, vol. 159, p. 104702, 2025.")
ref("[7] H. Lv and Y. Ding, \"A Hybrid Intrusion Detection System with "
    "K-Means and CNN+LSTM,\" EAI Endorsed Trans. Scalable Information "
    "Systems, vol. 11, no. 6, 2024.")
ref("[8] M. Tavallaee, E. Bagheri, W. Lu, and A. A. Ghorbani, \"A "
    "Detailed Analysis of the KDD CUP 99 Data Set,\" in Proc. IEEE CISDA, "
    "2009, pp. 1–6.")
ref("[9] Y. Jiang et al., \"MITRE ATT&amp;CK Applications in "
    "Cybersecurity and the Way Forward,\" arXiv:2502.10825, 2025.")
ref("[10] E. Albin and N. C. Rowe, \"A Realistic Experimental Comparison "
    "of the Suricata and Snort Intrusion Detection Systems,\" in Proc. "
    "IEEE WAINA, 2012, pp. 122–127.")
