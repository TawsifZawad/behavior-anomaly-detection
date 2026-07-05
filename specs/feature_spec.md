# Behavioral Feature Specification v2

## Project

**Cross-Platform Hybrid Behavior-Based Intrusion Detection System**

---

# Purpose

This document defines all behavioral features used by the proposed intrusion detection system. These features are shared across Windows, Ubuntu, and macOS whenever possible to provide a unified detection pipeline.

Each feature contains:

* Description
* Supported Operating Systems
* Collector Source
* Risk Category
* MITRE ATT&CK Mapping

---

# Feature Categories

## 1. Authentication

| Feature      | Description             | Windows | Ubuntu | macOS | MITRE |
| ------------ | ----------------------- | ------- | ------ | ----- | ----- |
| login_hour   | Average login time      | ✓       | ✓      | ✓     | -     |
| logout_hour  | Average logout time     | ✓       | ✓      | ✓     | -     |
| failed_login | Number of failed logins | ✓       | ✓      | ✓     | T1110 |

---

## 2. Initial Access

| Feature               | Description                   | Windows | Ubuntu | macOS | MITRE |
| --------------------- | ----------------------------- | ------- | ------ | ----- | ----- |
| usb_insert            | USB device connected          | ✓       | ✓      | ✓     | T1091 |
| internet_download     | File downloaded from Internet | ✓       | ✓      | ✓     | T1105 |
| download_then_execute | Downloaded file executed      | ✓       | ✓      | ✓     | T1105 |
| usb_then_execute      | Executable launched from USB  | ✓       | ✓      | ✓     | T1091 |

---

## 3. Script & Command Execution

| Feature                 | Description                              | Windows | Ubuntu | macOS | MITRE     |
| ----------------------- | ---------------------------------------- | ------- | ------ | ----- | --------- |
| powershell_started      | PowerShell launched                      | ✓       | -      | -     | T1059.001 |
| encoded_command         | Encoded or obfuscated command            | ✓       | ✓      | ✓     | T1027     |
| execution_policy_bypass | PowerShell execution policy bypass       | ✓       | -      | -     | T1059.001 |
| curl_pipe_bash          | Download piped directly to bash          | -       | ✓      | -     | T1059.004 |
| wget_then_execute       | File downloaded using wget then executed | -       | ✓      | -     | T1105     |

---

## 4. Suspicious Execution

| Feature             | Description                                | Windows | Ubuntu | macOS | MITRE |
| ------------------- | ------------------------------------------ | ------- | ------ | ----- | ----- |
| execution_from_temp | Executed from temporary/download directory | ✓       | ✓      | ✓     | T1204 |
| unsigned_binary     | Unsigned executable launched               | ✓       | -      | ✓     | T1553 |
| double_extension    | Executable with double extension           | ✓       | ✓      | ✓     | T1036 |
| hidden_process      | Hidden/background execution                | ✓       | ✓      | ✓     | T1564 |

---

## 5. LOLBins (Windows)

| Feature                | Description                         | Windows | Ubuntu | macOS | MITRE     |
| ---------------------- | ----------------------------------- | ------- | ------ | ----- | --------- |
| certutil_download      | Certutil used for download          | ✓       | -      | -     | T1105     |
| bitsadmin_download     | Bitsadmin download                  | ✓       | -      | -     | T1197     |
| rundll32_network       | Rundll32 executing network activity | ✓       | -      | -     | T1218.011 |
| regsvr32_remote_script | Regsvr32 executing remote script    | ✓       | -      | -     | T1218.010 |
| mshta_remote_script    | MSHTA executing remote HTA          | ✓       | -      | -     | T1218.005 |

---

## 6. Privilege Escalation

| Feature              | Description                  | Windows | Ubuntu | macOS | MITRE |
| -------------------- | ---------------------------- | ------- | ------ | ----- | ----- |
| privilege_escalation | Privilege escalation attempt | ✓       | ✓      | ✓     | T1548 |
| sudo_abuse           | Suspicious sudo usage        | -       | ✓      | ✓     | T1548 |

---

## 7. Reconnaissance

| Feature          | Description                          | Windows | Ubuntu | macOS | MITRE |
| ---------------- | ------------------------------------ | ------- | ------ | ----- | ----- |
| nmap_scan        | Nmap scan detected                   | -       | ✓      | ✓     | T1046 |
| hydra_bruteforce | Hydra brute-force attack             | -       | ✓      | ✓     | T1110 |
| ssh_bruteforce   | Repeated SSH authentication failures | -       | ✓      | ✓     | T1110 |

---

## 8. Persistence

| Feature               | Description                         | Windows | Ubuntu | macOS | MITRE     |
| --------------------- | ----------------------------------- | ------- | ------ | ----- | --------- |
| launchctl_persistence | LaunchAgent or LaunchDaemon created | -       | -      | ✓     | T1543     |
| osascript_shell       | AppleScript spawning shell          | -       | -      | ✓     | T1059.002 |

---

# Feature Types

## Raw Features

Collected directly from operating system logs.

Examples:

* usb_insert
* powershell_started
* internet_download
* certutil_download
* execution_from_temp
* privilege_escalation

---

## Derived Features

Generated by the Feature Extractor or Correlation Engine.

Examples:

* usb_then_execute
* download_then_execute
* encoded_command
* multiple_failed_logins
* living_off_the_land_activity

---

# Design Principles

1. Prefer behavioral context over process names.
2. Never classify an event as malicious using a single indicator.
3. Use correlated behaviors to determine attack stages.
4. Maintain feature compatibility across Windows, Ubuntu, and macOS whenever possible.
5. Map behavioral features to MITRE ATT&CK techniques for explainability.
