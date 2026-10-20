# Local Endpoint Detection & Response (EDR) Threat Lab

## 📌 Project Overview
Deployed a cloud-managed Endpoint Detection & Response (EDR) agent on a Windows host using **LimaCharlie**. Captured real-time system process telemetry, executed simulated privilege escalation tactics mapped to the **MITRE ATT&CK Framework**, authored custom multi-condition YAML detection rules, and triaged live process execution alerts.

---

## 🏗️ Technical Architecture & Telemetry Pipeline
```text
Windows Host (Local Machine)
   └── LimaCharlie Sensor Agent (HCP)
          └── Cloud Pipeline Telemetry Ingestion
                 └── Rule Detection Engine (YAML Rules)
                        └── Real-Time Incident Triage & Alerts
```

---

## ⚔️ Threat Simulations Executed (MITRE ATT&CK Mapping)
* **Persistence / Local Account Creation ([MITRE T1136.001](https://attack.mitre.org/techniques/T1136/001/)):** Executed local administrative account additions via elevated Command Prompt sessions (`net.exe user /add`).
* **Privilege Escalation ([MITRE T1078](https://attack.mitre.org/techniques/T1078/)):** Added newly created local entities into the local `Administrators` group.
* **Obfuscated / Encoded Command Execution ([MITRE T1027](https://attack.mitre.org/techniques/T1027/)):** Simulated encoded PowerShell command strings to verify endpoint visibility.

---

## 🔍 Custom Detection & Response (D&R) Rule Definition

```yaml
event: NEW_PROCESS
op: and
rules:
  - op: ends with
    path: event/FILE_PATH
    value: net.exe
    case sensitive: false
  - op: contains
    path: event/COMMAND_LINE
    value: /add
```

### Response Action:
```yaml
- action: report
  name: Suspicious Account Creation via Net.exe
```

---

## 🛡️ Incident Triage Workflow
1. **Rule Ingestion:** System monitored for new process generation events (`NEW_PROCESS`).
2. **Alert Trigger:** Flagged process execution where `FILE_PATH` matched `net.exe` combined with the `/add` command parameter.
3. **Process Tree Analysis:** Inspected parent-child relationships in the telemetry (`cmd.exe` -> `net.exe`) to confirm legitimacy.
4. **Remediation & Closure:** Removed unauthorized test user accounts via administrative command prompt (`net user test_soc_user2 /delete`) and validated system integrity.

---

## 🖼️ Lab Evidence & Screenshots

### Phase 1: LimaCharlie Cloud Infrastructure Setup
![LimaCharlie Organization](01-limacharlie-org.PNG)

### Phase 2: Active EDR Agent Sensor Connection
![EDR Agent Connected](02-edr-agent-connected.PNG)

### Phase 3: Detection & Response (D&R) Rule Configuration
![Detection Rule Definition](03-edr-detection-rule.PNG)

### Phase 4: Telemetry Alert & Process Execution Tree Triage
![Incident Detection Alert](04-edr-detection-alert.PNG)
