# Incident Simulation: Windows Attack Chain with Wazuh Detection

A writeup from a self-built SOC home lab. It documents a full attack chain against a monitored Windows endpoint — from tool ingress to log clearing — with detection, analysis, and a custom detection rule. Every stage is mapped to MITRE ATT&CK.

> **Nature of this material:** a controlled simulation in an isolated lab. All "attacks" were run manually on a dedicated test machine using benign commands and test files (no real malware). The objective was to practise detection and analysis, not to handle a real incident.

---

## 1. Lab environment

| Component | Details |
|---|---|
| SIEM/XDR | Wazuh 4.14.7 (all-in-one: indexer + manager + dashboard) |
| Server OS | Ubuntu Server 22.04 LTS, 192.168.122.125 |
| Monitored endpoint | Windows Server 2022 Standard (Desktop Experience) |
| Hostname / account | WIN-4TAN0OISED3 / Administrator (agent id 001) |
| Endpoint telemetry | Sysmon 15.21 (SwiftOnSecurity config) + native Windows logs |
| Virtualisation | QEMU/KVM, isolated libvirt NAT 192.168.122.0/24 |

**Audit policy enabled (critical for visibility):**
- Process creation auditing **with command line** (Event 4688 with full `commandLine`)
- PowerShell **Script Block Logging** (Event 4104)
- **Other Object Access Events** (Event 4698 — scheduled task creation)
- Channels collected: Security, System, Application, Sysmon/Operational, PowerShell/Operational, Windows Defender/Operational

**Security note:** Windows Defender real-time protection was deliberately disabled for the simulation so that attacks would reach analysis in Wazuh instead of being blocked at the endpoint. In an isolated lab this is standard practice when testing detection.

---

## 2. Attack chain summary

The scenario mirrors a typical intrusion in which each stage follows logically from the previous one: obtain code on the host → execute → establish persistence → escalate privileges → clear traces.

| # | Stage (ATT&CK tactic) | Technique | Event ID | rule.id | Level |
|---|---|---|---|---|---|
| 1 | Ingress Tool Transfer | T1105 | 4688 | **100100** (custom) | 12 |
| 2 | Execution / Discovery | T1059.001 / T1057 | 4104 | 91815 | 4 |
| 3 | Persistence | T1053.005 | 4698 | 60228 | 4 |
| 4 | Privilege Escalation | T1136.001 / T1098 | 4720 / 4732 | 92039 / 92033 | 3 |
| 5 | Defense Evasion | T1070.001 | 1102 | 63103 | 5 |

---

## 3. Incident timeline

All five stages were executed as a single, continuous attack chain on 2026-09-11, within a **5 min 37 s** window. The timeline order matches the kill-chain progression: ingress → execution → persistence → privilege escalation → defense evasion.

```
2026-09-11 21:39:39  [Stage 1] certutil downloads a file from the network   → T1105      (rule 100100, lvl 12)
        +3m 28s
2026-09-11 21:43:07  [Stage 2] PowerShell runs a Base64-encoded command     → T1059.001  (rule 91815,  lvl 4)
        +1m 20s
2026-09-11 21:44:27  [Stage 3] scheduled task created                       → T1053.005  (rule 60228,  lvl 4)
        +18s
2026-09-11 21:44:45  [Stage 4] local account created + added to admins      → T1136.001/T1098 (rule 92039/92033, lvl 3)
        +31s
2026-09-11 21:45:16  [Stage 5] Security event log cleared                   → T1070.001  (rule 63103,  lvl 5)
```

---

## 4. Stage-by-stage analysis

### Stage 1 — Ingress Tool Transfer (T1105)

**Action:**
```powershell
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/README.md C:\Users\Public\downloaded_file.txt
```

**Description:** `certutil.exe` is a legitimate, built-in Windows certificate utility abused as a **LOLBin** (Living off the Land Binary) to download files from the network. The attacker uses a trusted, already-present tool to avoid bringing their own downloader.

**Detection:** native Event 4688 (process creation with command line). The default ruleset had no dedicated high-severity alert for the *technique* — it only reacted incidentally via rule 92213 (level 15) to the *result*: an executable appearing in a folder commonly used by malware (Sysmon Event 11). To detect the technique itself regardless of where the file lands, a **custom rule 100100** was written (see section 5).

**Key evidence:** the `commandLine` field containing `-urlcache` and an external URL.

### Stage 2 — Execution: PowerShell encoded command (T1059.001)

**Action:**
```powershell
$cmd = "Write-Output 'attack simulation'; Get-Process | Select-Object -First 3"
$enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $enc
```

**Description:** Base64-encoding commands (`-EncodedCommand`) is a standard obfuscation technique meant to hide intent from simple analysis and filters.

**Detection:** Event 4104 (Script Block Logging), rule.id 91815. Key observation: **Script Block Logging captured the decoded, plaintext script content** even though it was launched in Base64 form. This demonstrates the value of the mechanism — it records what PowerShell actually executed, not the obfuscated input. The rule classified the event as "process discovery" (T1057) because the script contained `Get-Process`.

### Stage 3 — Persistence: scheduled task (T1053.005)

**Action:**
```powershell
schtasks /create /tn "WindowsUpdateHelper" /tr "calc.exe" /sc onlogon /ru System
```

**Description:** a scheduled task that runs a payload at every logon, surviving reboots. The name ("WindowsUpdateHelper") deliberately imitates a system component (**T1036 Masquerading**), and running as **SYSTEM** is an additional suspicious signal.

**Detection:** Event 4698, rule.id 60228, mapped to T1053.

**Operational finding:** Event 4698 was **not visible initially** — only Event 4688 (execution of `schtasks.exe`) appeared. The cause was the "Other Object Access Events" audit subcategory being disabled by default. After enabling it (`auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable`) and re-running the attack, Event 4698 appeared correctly. A real **gap in the default audit configuration** was identified and closed.

### Stage 4 — Privilege Escalation: account creation + admin add (T1136.001 / T1098)

**Action:**
```powershell
net user backdoor P@ssw0rd123! /add
net localgroup Administrators backdoor /add
```

**Description:** creating an attacker-controlled account (persistent, "legitimate-looking" access) and escalating by adding it to the Administrators group.

**Detection — one action, multiple traces:**
- Event 4720 (account created), rule.id 92039
- Event 4732 (added to Administrators group), rule.id 92033
- Sysmon Event 1 — execution of `net.exe localgroup Administrators backdoor`

**Key analyst finding (rule mis-classification):** the Sysmon rule described the `net.exe` execution as an *"account discovery command"* (implying T1087 — reconnaissance). This is a **mis-classification**: analysis of the `commandLine` field (`net localgroup Administrators backdoor` — with an account name, no read-only flag) clearly indicates **adding** the account to the group, i.e. manipulation/escalation (T1098 / T1136), not discovery. The rule likely fires on the mere presence of `net` + `localgroup` + `Administrators`, without distinguishing a read from a write. The verdict was based on the raw command content, not the rule label. In production, such a rule should be flagged for tuning.

### Stage 5 — Defense Evasion: clearing the log (T1070.001)

**Action:**
```powershell
wevtutil cl Security
```

**Description:** covering tracks by clearing the Security event log. Legitimate administrators almost never do this manually, so **Event 1102 is one of the strongest single signals** in monitoring.

**Detection:** Event 1102, rule.id 63103, mapped to T1070.001.

**Key finding — the value of log centralisation:** after the Security log was cleared, all earlier events disappeared locally from the host but **remained in Wazuh**, because the agent had shipped them to the server in real time. A practical illustration of a fundamental SIEM principle: an attacker can wipe local logs but cannot reach the copy already ingested by the central system.

---

## 5. Custom detection rule (detection engineering)

The default ruleset detected the *result* of the certutil attack (a file in a suspicious folder) but not the download *technique* itself. The rule below (`/var/ossec/etc/rules/local_rules.xml`) detects the behavioural pattern — certutil with a download parameter — regardless of where the file lands, and maps it to T1105.

```xml
<group name="windows,attack,custom,">
  <rule id="100100" level="12">
    <if_sid>67027</if_sid>
    <field name="win.eventdata.newProcessName" type="pcre2">(?i)certutil\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)urlcache|verifyctl</field>
    <description>LOLBin abuse: certutil downloading a file from the network (MITRE T1105)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>
</group>
```

**Logic:**
- `if_sid 67027` — builds on the Wazuh rule for process creation (Event 4688)
- first `field` — process name ends with `certutil.exe`
- second `field` — command line contains `urlcache` or `verifyctl` (download parameters)
- both conditions must hold (AND) — limits false positives from legitimate certificate use of certutil

**Testing and deployment:** rule syntax was validated with `wazuh-logtest`, the manager was reloaded (`systemctl restart wazuh-manager`), and the rule was confirmed firing (level 12, T1105 tag) on a re-run of the attack.

**Advantage over the default rule:** rule 100100 detects certutil even when it downloads a file to an ordinary folder — where rule 92213 (file in a malware-common directory) would not react at all. Detection of the technique, not the result.

---

## 6. Analyst findings

The most valuable observations from the whole simulation — beyond simple "attack → alert":

1. **Detecting the result vs detecting the technique.** The default ruleset caught the effect of the certutil attack (a file in a suspicious folder) but not the technique itself. A custom rule mapped to T1105 closed that gap.

2. **Default audit configuration has gaps.** Event 4698 (task creation) was not logged until the relevant audit subcategory was enabled. Important techniques can pass unnoticed without deliberate telemetry configuration.

3. **A rule's description is an interpretation, not ground truth.** The `net.exe` rule mis-classified privilege escalation as reconnaissance. Verdicts must rest on raw data (`commandLine`), not the alert label.

4. **One action leaves multiple traces.** Almost every stage was visible simultaneously in native Windows telemetry and in Sysmon. Analytical confidence is built by correlating sources, not from a single alert.

5. **Log centralisation defeats track-clearing.** Clearing the local log (T1070.001) did not remove events already shipped to the SIEM.

6. **Time synchronisation is a prerequisite for a reliable timeline.** Endpoint clock drift caused events to "disappear" from the dashboard time window; after synchronisation (w32time/NTP) the timestamps became consistent. Time discrepancy can also be a deliberate attacker action (timestomping, T1070.006).

---

## 7. Skills demonstrated

- Deploying and configuring a SIEM/XDR (Wazuh) from scratch, including endpoint telemetry onboarding and tuning (Sysmon, Windows audit policy)
- Simulating ATT&CK techniques and detecting them (T1105, T1059.001, T1053.005, T1136.001, T1098, T1070.001)
- Event triage and analysis: reading fields, correlating sources, forming evidence-based verdicts
- Detection engineering: writing, testing, and deploying a custom rule mapped to ATT&CK
- Critical assessment of detection quality (spotting a mis-classification and an audit gap)
- Operational troubleshooting (services, install logs, time synchronisation)

---

*Lab built as part of independent preparation for a SOC Analyst role. Isolated environment; all actions controlled and benign.*
