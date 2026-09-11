# SOC Home Lab — Windows Attack Chain Detection with Wazuh

A self-built detection lab documenting a full attack chain against a monitored Windows endpoint — from tool ingress to log clearing — with detection, analysis, and a custom detection rule. Every stage is mapped to MITRE ATT&CK.

Built as part of my hands-on preparation for a SOC Analyst role. All activity was performed in an isolated lab using benign commands and test files (no real malware); the goal was to practice detection and analysis, not to respond to a real incident.

---

## What this repository shows

- Deploying and configuring a SIEM/XDR (Wazuh) from scratch, including endpoint telemetry tuning (Sysmon, Windows audit policy)
- Simulating and detecting a chained set of MITRE ATT&CK techniques
- Event triage and analysis: reading raw fields, correlating sources, forming an evidence-based verdict
- **Detection engineering**: writing, testing, and deploying a custom rule mapped to ATT&CK
- Critically assessing detection quality — spotting a mis-classified rule and an audit-policy gap

---

## Lab architecture

```
                 ┌─────────────────────────────┐
                 │      Wazuh 4.14.7 (AIO)      │
                 │  indexer + manager + dash    │
                 │  Ubuntu Server 22.04         │
                 │  192.168.122.125             │
                 └──────────────┬──────────────┘
                                │  agent enrollment / log shipping
                                │
                 ┌──────────────┴──────────────┐
                 │   Windows Server 2022 (GUI)  │
                 │   WIN-4TAN0OISED3 (agent 001)│
                 │   Sysmon 15.21 + Win auditing│
                 └─────────────────────────────┘

     Virtualisation: QEMU/KVM · isolated libvirt NAT 192.168.122.0/24
```

**Telemetry sources collected:** Security, System, Application, Sysmon/Operational, PowerShell/Operational, Windows Defender/Operational.

**Audit policy enabled for visibility:**
- Process creation **with command line** (Event 4688)
- PowerShell **Script Block Logging** (Event 4104)
- **Other Object Access Events** (Event 4698 — scheduled task creation)

---

## Contents

| File | Description |
|---|---|
| [`incident-writeup.md`](incident-writeup.md) | Full incident writeup: attack chain, timeline, per-stage analysis, analyst findings |
| [`detection/local_rules.xml`](detection/local_rules.xml) | Custom Wazuh detection rule (T1105 — certutil LOLBin abuse) |
| [`screenshots/`](screenshots/) | Folder with dashboards captures per stage |
---

## Attack chain at a glance

| # | Stage (ATT&CK tactic) | Technique | Event ID | rule.id | Level |
|---|---|---|---|---|---|
| 1 | Ingress Tool Transfer | T1105 | 4688 | **100100** (custom) | 12 |
| 2 | Execution / Discovery | T1059.001 / T1057 | 4104 | 91815 | 4 |
| 3 | Persistence | T1053.005 | 4698 | 60228 | 4 |
| 4 | Privilege Escalation | T1136.001 / T1098 | 4720 / 4732 | 92039 / 92033 | 3 |
| 5 | Defense Evasion | T1070.001 | 1102 | 63103 | 5 |

Full analysis in the [incident writeup](incident-writeup.md).

---

## Detection engineering highlight

The default ruleset detected the *result* of the certutil attack (an executable dropped in a folder commonly used by malware) but not the *technique* itself. I wrote a custom rule that detects the behavioural pattern — certutil invoked with a download parameter — regardless of where the file lands, and maps it to T1105. See [`detection/local_rules.xml`](detection/local_rules.xml).

---

*Isolated lab; all actions controlled and benign. This lab extends the practical testbed work from my MSc thesis on wireless security.*
