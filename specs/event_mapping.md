# Event Mapping Specification v2

## Project

**Cross-Platform Hybrid Behavior-Based Intrusion Detection System**

---

# Purpose

This document defines how operating system specific logs are normalized into a unified event format.

Different operating systems generate different event IDs, log formats, and audit records. To ensure platform independence, all collectors convert native events into a common event model before feature extraction.

The Feature Extractor, Rule Engine, Machine Learning module, and Correlation Engine operate only on normalized events.

---

# Unified Event Model

Every operating system must produce events using the following format.

| Field      | Description                    |
| ---------- | ------------------------------ |
| timestamp  | Event timestamp                |
| username   | User associated with the event |
| os         | Windows / Ubuntu / macOS       |
| event_type | Normalized event name          |
| source     | Original log source            |
| ip         | Remote IP if available         |
| details    | Original event details         |

---

# Windows Event Mapping

| Windows Source | Event ID | Normalized Event     |
| -------------- | -------- | -------------------- |
| Security       | 4624     | LOGIN_SUCCESS        |
| Security       | 4625     | LOGIN_FAILED         |
| Security       | 4634     | LOGOUT               |
| Security       | 4688     | PROCESS_START        |
| Security       | 4689     | PROCESS_END          |
| Security       | 4672     | PRIVILEGE_ESCALATION |
| Security       | 6416     | USB_INSERT           |
| Sysmon         | 1        | PROCESS_START        |
| Sysmon         | 3        | NETWORK_CONNECTION   |
| Sysmon         | 11       | FILE_CREATED         |
| Sysmon         | 13       | REGISTRY_MODIFIED    |

---

# Ubuntu Event Mapping

| Log Source   | Normalized Event     |
| ------------ | -------------------- |
| auth.log     | LOGIN_SUCCESS        |
| auth.log     | LOGIN_FAILED         |
| auth.log     | LOGOUT               |
| journalctl   | PROCESS_START        |
| journalctl   | PROCESS_END          |
| auditd       | PRIVILEGE_ESCALATION |
| udev         | USB_INSERT           |
| bash_history | COMMAND_EXECUTION    |
| apt          | PACKAGE_INSTALL      |

---

# macOS Event Mapping

| Log Source     | Normalized Event     |
| -------------- | -------------------- |
| Unified Log    | LOGIN_SUCCESS        |
| Unified Log    | LOGIN_FAILED         |
| Unified Log    | LOGOUT               |
| Unified Log    | PROCESS_START        |
| Unified Log    | PROCESS_END          |
| Unified Log    | PRIVILEGE_ESCALATION |
| IOKit          | USB_INSERT           |
| LaunchServices | APPLICATION_START    |
| LaunchAgents   | PERSISTENCE_CREATED  |

---

# Normalized Event Types

The following event types are shared across all supported operating systems whenever possible.

## Authentication

* LOGIN_SUCCESS
* LOGIN_FAILED
* LOGOUT

---

## Process Activity

* PROCESS_START
* PROCESS_END
* COMMAND_EXECUTION

---

## File Activity

* FILE_CREATED
* FILE_ACCESS
* FILE_MODIFIED
* FILE_DELETED

---

## Device Activity

* USB_INSERT
* USB_REMOVE
* USB_EXECUTABLE_RUN

---

## Network Activity

* NETWORK_CONNECTION
* INTERNET_DOWNLOAD

---

## Privilege Activity

* PRIVILEGE_ESCALATION
* SUDO_EXECUTION

---

## Persistence Activity

* PERSISTENCE_CREATED
* REGISTRY_MODIFIED
* SERVICE_CREATED

---

# Collector Responsibilities

Each collector must:

1. Read native operating system logs.
2. Identify supported security events.
3. Convert native events into the normalized event model.
4. Preserve original details inside the `details` field.
5. Store normalized events in the database.

Collectors must not perform:

* Risk analysis
* Feature extraction
* Machine learning prediction
* Threat correlation

These tasks belong to later stages of the detection pipeline.

---

# Design Principles

1. Operating system differences must remain inside collectors.
2. Higher-level modules should never depend on native event IDs.
3. All behavioral analysis must use normalized events.
4. Original log information should always be preserved for forensic investigation.
