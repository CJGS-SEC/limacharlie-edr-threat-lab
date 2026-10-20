# Local Endpoint Detection & Response (EDR) Threat Lab

## Project Overview
Deployed a cloud-managed Endpoint Detection & Response (EDR) agent on a Windows host using **LimaCharlie**. Captured real-time system process telemetry, executed simulated privilege escalation tactics mapped to the **MITRE ATT&CK Framework**, authored custom multi-condition YAML detection rules, and triaged live process execution alerts.

---

## Technical Architecture & Telemetry Pipeline
```text
Windows Host (Local Machine)
   └── LimaCharlie Sensor Agent (HCP)
          └── Cloud Pipeline Telemetry Ingestion
                 └── Rule Detection Engine (YAML Rules)
                        └── Real-Time Incident Triage & Alerts
```
Threat Simulations Executed (MITRE ATT&CK Mapping)
Persistence / Local Account Creation (MITRE T1136.001): Executed local administrative account additions via elevated Command Prompt sessions (net.exe user /add).

Privilege Escalation (MITRE T1078): Added newly created local entities into the local Administrators group.

Obfuscated / Encoded Command Execution (MITRE T1027): Simulated encoded PowerShell command strings to verify endpoint visibility.

Custom Detection & Response (D&R) Rule Definition
YAML
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
Response Action:
YAML
- action: report
  name: Suspicious Account Creation via Net.exe
Rule Tuning & Engineering Lessons
Path Matching Logic: During initial testing, strict string matching on process paths can cause false negatives if executables are invoked from non-standard directories or system aliases. Using ends with for FILE_PATH alongside case-insensitive matching (case sensitive: false) ensured reliable telemetry ingestion across different CLI environments.

Noise Reduction: Matching strictly on net.exe would generate high alert volume for legitimate admin activity. Pairing it with the /add command line string ensured the rule targets specific account creation events rather than general system queries.

Incident Triage Workflow
Rule Ingestion: System monitored for new process generation events (NEW_PROCESS).

Alert Trigger: Flagged process execution where FILE_PATH matched net.exe combined with the /add command parameter.

Process Tree Analysis: Inspected parent-child relationships in the telemetry (cmd.exe -> net.exe) to confirm legitimacy.

Remediation & Closure: Removed unauthorized test user accounts via administrative command prompt (net user test_soc_user2 /delete) and validated system integrity.

Lab Evidence & Screenshots
Phase 1: LimaCharlie Cloud Infrastructure Setup
Phase 2: Active EDR Agent Sensor Connection
Phase 3: Detection & Response (D&R) Rule Configuration
Phase 4: Telemetry Alert & Process Execution Tree Triage
