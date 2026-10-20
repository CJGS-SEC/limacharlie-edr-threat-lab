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
