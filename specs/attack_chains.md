# Attack Chain Specification v2

## Project

**Cross-Platform Hybrid Behavior-Based Intrusion Detection System**

---

# Purpose

This document defines multi-stage attack chains used by the Correlation Engine.

Unlike traditional IDS solutions that evaluate isolated events, the proposed system correlates multiple behavioral indicators before determining the final threat severity.

Each attack chain consists of:

* Triggering behaviors
* Attack progression
* Threat severity
* MITRE ATT&CK mapping

---

# Attack Chain 1 – USB Malware Execution

### Flow

USB Insert

↓

USB Executable

↓

Unsigned Binary

↓

Execution From Temporary Directory

↓

Privilege Escalation

### Severity

**CRITICAL**

### MITRE ATT&CK

* T1091 – Replication Through Removable Media
* T1204 – User Execution
* T1548 – Abuse Elevation Control Mechanism

---

# Attack Chain 2 – PowerShell Attack

### Flow

PowerShell Started

↓

Encoded Command

↓

Execution Policy Bypass

↓

Internet Download

↓

Download Then Execute

### Severity

**CRITICAL**

### MITRE ATT&CK

* T1059.001 – PowerShell
* T1027 – Obfuscated Files or Information
* T1105 – Ingress Tool Transfer

---

# Attack Chain 3 – Living-off-the-Land (LOLBins)

### Flow

CertUtil Download

OR

BitsAdmin Download

OR

MSHTA Remote Script

↓

Downloaded File Executed

↓

Hidden Process

### Severity

**HIGH**

### MITRE ATT&CK

* T1105
* T1218
* T1564

---

# Attack Chain 4 – Linux Malware Installation

### Flow

Internet Download

↓

curl | bash

OR

wget + chmod + execute

↓

Privilege Escalation

### Severity

**CRITICAL**

### MITRE ATT&CK

* T1105
* T1059.004
* T1548

---

# Attack Chain 5 – SSH Brute Force

### Flow

Multiple Failed Logins

↓

SSH Brute Force

↓

Privilege Escalation

### Severity

**HIGH**

### MITRE ATT&CK

* T1110
* T1548

---

# Attack Chain 6 – Network Reconnaissance

### Flow

Nmap Scan

↓

Hydra Brute Force

↓

Successful Authentication

### Severity

**HIGH**

### MITRE ATT&CK

* T1046
* T1110

---

# Attack Chain 7 – Internet Download and Execution

### Flow

Internet Download

↓

Downloaded File Executed

↓

Execution From Temporary Directory

### Severity

**HIGH**

### MITRE ATT&CK

* T1105
* T1204

---

# Attack Chain 8 – Persistence

### Flow

Privilege Escalation

↓

Persistence Created

↓

Hidden Process

### Severity

**CRITICAL**

### MITRE ATT&CK

* T1548
* T1543
* T1564

---

# Correlation Rules

The Correlation Engine must never classify an attack based on a single event.

Instead, multiple related behaviors must be correlated before assigning HIGH or CRITICAL severity.

---

# Design Principles

1. Single events should generate low confidence.
2. Multiple correlated behaviors significantly increase confidence.
3. Context is more important than individual process names.
4. Cross-platform behavioral patterns should be preferred whenever possible.
5. Every attack chain should be explainable using MITRE ATT&CK techniques.
