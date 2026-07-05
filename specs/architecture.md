# System Architecture Specification v2

## Project

**Cross-Platform Hybrid Context-Aware Intrusion Detection System**

---

# Overview

The proposed system is a hybrid behavior-based intrusion detection system that combines:

* Rule-Based Detection
* Machine Learning
* Behavioral Correlation
* Context-Aware Analysis

The system supports multiple operating systems including Windows, Ubuntu, and macOS through a unified event model.

---

# Overall Architecture

```text
                   +----------------------+
                   |   Windows Collector  |
                   +----------------------+
                               |
                   +----------------------+
                   |   Ubuntu Collector   |
                   +----------------------+
                               |
                   +----------------------+
                   |    macOS Collector   |
                   +----------------------+
                               |
                               v
                    +--------------------+
                    | Event Normalization|
                    +--------------------+
                               |
                               v
                    +--------------------+
                    | Event Database     |
                    +--------------------+
                               |
                               v
                    +--------------------+
                    | Event Aggregator   |
                    +--------------------+
                               |
                               v
                    +--------------------+
                    | Feature Extractor  |
                    +--------------------+
                               |
                               v
                    +--------------------+
                    | Feature Vector     |
                    +--------------------+
                               |
                +--------------+--------------+
                |                             |
                v                             v
       +----------------+            +----------------+
       | Baseline Engine|            | ML Predictor   |
       +----------------+            +----------------+
                |                             |
                +--------------+--------------+
                               |
                               v
                    +--------------------+
                    | Behavior Comparator|
                    +--------------------+
                               |
                               v
                    +--------------------+
                    | Risk Engine        |
                    +--------------------+
                               |
                               v
                    +--------------------+
                    | Correlation Engine |
                    +--------------------+
                               |
                               v
                    +--------------------+
                    | Decision Engine    |
                    +--------------------+
                               |
                               v
                    +--------------------+
                    | Alert Manager      |
                    +--------------------+
```

---

# Processing Pipeline

## Step 1 – Event Collection

Operating system collectors monitor security events and collect native logs.

Supported platforms:

* Windows
* Ubuntu
* macOS

---

## Step 2 – Event Normalization

Native operating system events are converted into a common event format.

Example:

Windows Event ID 4624

↓

LOGIN_SUCCESS

Ubuntu auth.log

↓

LOGIN_SUCCESS

macOS Unified Log

↓

LOGIN_SUCCESS

---

## Step 3 – Event Storage

Normalized events are stored inside the local event database.

The database acts as the central source for feature extraction.

---

## Step 4 – Event Aggregation

Events are grouped by username before feature extraction.

Example:

```text
Rahim
 ├── LOGIN_SUCCESS
 ├── FILE_ACCESS
 ├── USB_INSERT
 └── PROCESS_START

Karim
 ├── LOGIN_SUCCESS
 ├── LOGOUT
 └── FILE_ACCESS
```

---

## Step 5 – Feature Extraction

Behavioral features are generated from grouped events.

Examples:

* login_hour
* failed_login
* internet_download
* execution_from_temp
* privilege_escalation

The output is a Feature Vector.

---

## Step 6 – Baseline Comparison

Current user behavior is compared with the learned behavioral baseline.

Behavioral differences are calculated for every feature.

---

## Step 7 – Machine Learning

Isolation Forest analyzes the current feature vector.

Output:

* NORMAL
* ANOMALY

with confidence score.

---

## Step 8 – Rule-Based Risk Analysis

Risk Engine evaluates behavioral deviations using expert-defined rules.

Output:

* Risk Score
* Risk Level
* Human-readable reasons

---

## Step 9 – Behavioral Correlation

Individual events are combined into multi-stage attack chains.

Examples:

* USB → Execute → Privilege Escalation
* PowerShell → Encoded Command → Download
* Nmap → Hydra → SSH Brute Force

---

## Step 10 – Final Decision

Decision Engine combines:

* Baseline comparison
* Risk score
* Machine learning prediction
* Correlation results

Final status:

* SAFE
* NORMAL
* REVIEW
* SUSPICIOUS
* CRITICAL

---

## Step 11 – Alert Generation

Structured JSON alerts are generated.

Each alert contains:

* Timestamp
* Username
* Risk Score
* Risk Level
* ML Prediction
* Final Decision
* Reasons
* Correlated Attack Chains

---

# Design Principles

The system follows the following principles:

1. Cross-platform compatibility.
2. Context-aware behavioral analysis.
3. Hybrid detection using rules and machine learning.
4. Multi-stage attack correlation.
5. Explainable security decisions.
6. MITRE ATT&CK alignment.
7. Modular and extensible architecture.

---

# Future Extensions

The architecture allows future integration of:

* Real-time event streaming
* SIEM platforms
* Threat intelligence feeds
* Deep learning models
* Graph-based attack correlation
* Web dashboard
* REST API
* Distributed multi-host monitoring

without major architectural changes.
