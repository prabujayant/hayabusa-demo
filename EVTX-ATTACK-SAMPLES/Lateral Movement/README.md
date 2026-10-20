# Lab 3 — Lateral Movement: "Follow the Admin Share"

**Duration:** 20 minutes
**Data:** 47 `.evtx` files recorded while attackers moved from one host to others
**Tool:** Hayabusa v4.2.0 (in the demo root, two levels up)

> This is a standalone lab. The main instructor guide is [../../README.md](../../README.md).
> The prerequisite lab is [Privilege Escalation](<../Privilege Escalation/README.md>).

---

## Learning objectives

By the end of 20 minutes students should be able to:

1. Explain why **lateral movement** is the moment a single compromised workstation becomes an incident.
2. Read an **Impacket `wmiexec`** command line and identify it from its shape alone.
3. Tell **WMI**, **DCOM**, **SMB/PsExec** and **WinRM** apart using the *parent process* — not the command line.
4. Recognise **anti-forensics**: `RunMRU` deletion and Event ID **1102** (log cleared).
5. Answer: *which host should you isolate first, and why is it not the one with the most alerts?*

---

## Before you start

Run everything from the **demo root** (the folder containing `hayabusa.exe`).

```powershell
cd C:\hayabusa-demo
```

> **Important:** if you `cd` into a tactic folder and run `..\..\hayabusa.exe`, Hayabusa cannot find `rules` and produces **no CSV at all** — just a banner. Stay in the demo root, or pass `-r ..\..\rules -c ..\..\rules\config`.

Optional pre-flight (should take 12–17 s depending on disk cache):

```powershell
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Lateral Movement" -o lm.csv -w
```

Delete `lm.csv` before class.

---

## Demo timeline

| # | Step | Time |
|---|---|---|
| 1 | Set the scene: crown jewels | 2 min |
| 2 | Run the scan | 3 min |
| 3 | Impacket vs CrackMapExec — same command, different parent | 4 min |
| 4 | PsExec over IPC$ — the remote source IP | 3 min |
| 5 | The named-pipe zoo (and the one critical finding) | 3 min |
| 6 | Covering tracks: RunMRU + log cleared | 3 min |
| 7 | Worksheet + answers | 2 min |

---

## Step 1 — Set the scene (2 min)

> "The attacker has SYSTEM on one workstation. Why do we care? Because a workstation is not the goal — **the domain is**."

Ask: *"What is the first thing an attacker needs before they can move to a second host?"*

The answer chain to draw on the board:

```
valid credentials  ->  a way to use them remotely  ->  a service that executes for you
```

Windows gives an attacker **many** ways to execute on a remote host using only valid credentials — that is exactly why lateral movement is so hard to stop:

| Technique | Remote execution via | MITRE |
|---|---|---|
| SMB / PsExec | `ADMIN$` share + service creation | T1021.002 |
| WMI | `Win32_Process::Create` | T1047 |
| DCOM | MMC / ShellWindows / ShellBrowserWindow | T1021.003 |
| WinRM | PowerShell Remoting, `wsmprovhost` | T1021.006 |
| Scheduled task | `ATSVC` RPC | T1053 |
| MSSQL | `xp_cmdshell` | T1505.001 |

> **Say this:** "Every one of these is a *legitimate administrative feature*. That is the whole problem — you cannot just block them without breaking IT."

---

## Step 2 — Run the scan (3 min)

```powershell
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Lateral Movement" -o lm.csv -H lm.html -w
```

Measured output (11–17 seconds, warm vs cold disk cache):

```
Total event log files: 47
Total detection rules: 4,674
Total | Unique detections: 1,238 | 89
Total | Unique critical detections: 1
Total | Unique high detections:     92
Total | Unique medium detections:   54
Total | Unique low detections:      53
Total | Unique informational:    1,038
```

> **Say this:** "1,238 detections — and **1,038 of them are informational**. This is the reality of a real SOC. Your job is not to read 1,238 rows; it is to collapse them to the dozen that matter. That is *triage*, and it is a skill, not a button."

Top rules for the whole folder:

```powershell
Import-Csv .\lm.csv | Where-Object { $_.Level -in @('crit','high') } |
    Group-Object RuleTitle | Sort-Object Count -Descending |
    Select-Object Count, Name -First 12 | Format-Table -AutoSize
```

| Rule | Count | Level |
|---|---|---|
| RunMRU Registry Key Deletion - Registry | 21 | high |
| HackTool - Potential Impacket Lateral Movement Activity | 9 | high |
| Suspicious Redirection to Local Admin Share | 6 | high |
| HackTool - CrackMapExec Execution Patterns | 6 | high |
| First Time Seen Remote Named Pipe | 5 | high |
| Log Cleared | 5 | high |
| MMC Spawning Windows Shell | 3 | high |
| Suspicious PsExec Execution | 3 | high |

---

## Step 3 — Impacket vs CrackMapExec (4 min)

Two different tools, **almost the same command line**. This is the best comparison in the whole dataset.

### Impacket (`wmiexec.py`)

```powershell
Import-Csv .\lm.csv | Where-Object RuleTitle -like '*Impacket*' |
    Select-Object Timestamp, Computer, EventID | Format-Table -AutoSize
```

9 detections. Now the evidence — one line explains the whole technique:

```powershell
Import-Csv .\lm.csv | Where-Object RuleTitle -like '*Impacket*' |
    Select-Object -First 1 -ExpandProperty Details
```

```
Cmdline:       "C:\Windows\System32\cmd.exe" /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1
ParentCmdline: C:\Windows\system32\mmc.exe -Embedding
Proc:          C:\Windows\System32\cmd.exe
```

Decode it for the class, part by part:

| Fragment | Meaning |
|---|---|
| `cmd.exe /Q /c` | Quiet command shell; `/Q` turns echo off (no output noise) |
| `cd \ 1> \\host\ADMIN$\__<epoch>` | Run a command and **redirect output back through the ADMIN$ share** |
| `__1556656511.61` | Unix epoch + random suffix = a unique output file per command |
| Parent `mmc.exe -Embedding` | The shell was launched by **DCOM/WMI**, not by a user |

> **Say this:** "This is `wmiexec`. The attacker never runs an interactive shell — each command writes its output to a file in `ADMIN$` and reads it back. From the victim's point of view it looks like a normal `cmd.exe` with a weird **mmc.exe** parent."

### CrackMapExec

```powershell
Import-Csv .\lm.csv | Where-Object RuleTitle -like '*CrackMapExec*' |
    Select-Object -First 1 -ExpandProperty Details
```

```
Cmdline:       cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1556656369.7 2>&1
ParentCmdline: C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding
```

**Now put them side by side on the board:**

| | Impacket | CrackMapExec |
|---|---|---|
| Command line | identical shape | identical shape |
| Parent process | `mmc.exe -Embedding` (DCOM) | `wmiprvse.exe -secured -Embedding` (WMI) |
| MITRE | T1047 · T1021.003 | T1047 · T1053 · T1059.003 · T1059.001 · S0106 |

> **Say this:** "The **command line cannot tell these apart** — the tools deliberately copy each other. The **parent process** is what tells you which API the attacker used. This is why detection engineering needs process ancestry, not just command-line grep. And it is why `Sysmon Event ID 1` with `ParentImage` is the single most valuable field in Windows DFIR."

The third related rule, `Suspicious Redirection to Local Admin Share` (6 hits, tagged `Exfil` · **T1048**), fires on the very same `1> \\host\ADMIN$` redirection — the same behaviour seen from the **data-flow** angle instead of the tool angle.

> **Say this:** "One event, three rules, three perspectives: which tool, which API, which data flow. That is defence in depth in detection."

---

## Step 4 — PsExec over IPC$ (3 min)

```powershell
Import-Csv .\lm.csv | Where-Object RuleTitle -like '*PsExec*' |
    Select-Object Timestamp, Computer, EventID, Details | Format-List
```

```
Timestamp: 2019-01-19 18:30:10  Computer: IEWIN7  EventID: 5145
ShareName: \\*\IPC$
Path:      blabla-NLLT108334-37048-stdin
SrcUser:   IEUser
SrcIP:     10.0.2.16
```

Explain the three signals:

1. **Event 5145** on `IPC$` — the "hidden" share used for named-pipe chatter. Access to `IPC$` is *normal* admin behaviour, which is what makes it a good hiding place.
2. **`-stdin` / `-stdout` pipe names** — PsExec creates a pair of named pipes per remote command so it can pipe input and collect output. Random prefix + `NLLT` + numbers is the PsExec pattern.
3. **`SrcIP: 10.0.2.16`** — this is a **remote** address. Compare with Step 3, where `SrcIP` was `127.0.0.1` (loopback, attacker already on the host).

> **Say this:** "`127.0.0.1` means the tool is running *on* this machine — a proxy, a relay, or a hop. A real `10.x` address means somebody else is reaching in. That single field tells you whether you are looking at the entry point or at a victim."

Also show the service-installation counterpart. Note the **uppercase** keyword — keyword search is case-sensitive:

```powershell
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES\Lateral Movement" -k PSEXESVC
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES\Lateral Movement" -k psexesvc -i    # same, case-insensitive
```

Both return **2 findings** (the renamed `PSEXESVC` service registration). Without `-i`, the lowercase search returns 0 — a classic silent failure.

---

## Step 5 — The named-pipe zoo (3 min)

Named pipes are how Windows does inter-process communication — and therefore how most remote execution works.

```powershell
Import-Csv .\lm.csv | Where-Object RuleTitle -match 'Named Pipe' |
    Select-Object Timestamp, RuleTitle, Computer, Level | Format-Table -AutoSize
```

The folder contains the **Printer Bug / PetPotam-style** relay sample too:

```
First Time Seen Remote Named Pipe   (5 hits, LatMov · T1021.002)
  2021-04-21  Computer: MSEDGEWIN10  EventID: 5145
  ShareName: \\*\IPC$   Path: samir   SrcUser: user03   SrcIP: 127.0.0.1
```

And the single **critical** finding in this folder:

```powershell
Import-Csv .\lm.csv | Where-Object Level -eq 'crit' | Format-List
```

```
RuleTitle:    Malicious Named Pipe Created
Computer:     IEWIN7        EventID: 18 (Sysmon)
Pipe:         \46a676ab7f179e511e30dd2dc41bd388
Proc:         System         PID: 4
Tags:         T1055
```

> **Say this:** "A pipe name that is a 32-character hex hash, created by **PID 4 (System)** with no owning process image — that is a remote-access trojan's control channel. Legitimate software names its pipes: `srvsvc`, `lsarpc`, `spoolss`. Attackers hash theirs so you cannot signature them by name."

Why this matters: **every** lateral movement tool in this folder eventually creates a named pipe. That makes pipes the most reliable *common denominator* signal.

---

## Step 6 — Covering tracks (3 min)

```powershell
Import-Csv .\lm.csv | Where-Object RuleTitle -eq 'Log Cleared' |
    Select-Object Timestamp, Computer, EventID | Format-Table -AutoSize
```

```
2019-03-18 16:36:25  PC01.example.corp              1102
2019-03-19 05:32:00  WIN-77LTAPHIQ1R.example.corp    1102
```

> **Say this:** "Event ID **1102** is *'the audit log was cleared'*. Think about what that means: the attacker **deleted the evidence**. Two things follow. First, `1102` is itself a **high-severity alert** — destroying the log is louder than the crime. Second, the log you are holding may be incomplete, which is exactly why we also detect the *deletion of specific artefacts*."

That second point is the `RunMRU` rule — **21 detections, all on `MSEDGEWIN10`**:

```powershell
Import-Csv .\lm.csv | Where-Object RuleTitle -like '*RunMRU*' |
    Group-Object Computer | ForEach-Object { "$($_.Name) x$($_.Count)" }
```

> **Say this:** "`RunMRU` is the *'recently typed in Start > Run'* list. Attackers delete it so the next investigator cannot see they typed `psexec \\target`. The deletion is a **registry event**, tagged **T1070.003 — Indicator Removal**. You cannot delete it quietly, because the deletion is logged too."

Final triage question: `PC01.example.corp` has **910 events** (the most in the folder), and it was also a log-clearing victim — but the DC `DC1.insecurebank.local` has only **5**. Ask the class which to isolate first.

> **Answer:** the DC. Alert volume measures *how noisy a host is*, not *how important it is*. A domain controller with 5 suspicious events is a far bigger emergency than a workstation with 910 — because the DC holds every credential in the domain.

---

## Worksheet (hand out during Step 7)

1. Write the Impacket command line from memory. What part of it reveals the output channel?
2. Impacket and CrackMapExec produced nearly identical command lines. What single field distinguished them, and why does that field exist?
3. `SrcIP` was `127.0.0.1` for Impacket but `10.0.2.16` for PsExec. What does each tell you about the attacker's position?
4. An attacker clears the Security log with `wevtutil cl Security`. What Event ID do you hunt for, and what cannot the attacker remove?
5. The top host has 910 events, `DC1` has 5. Which do you isolate first and why?

### Answer key

1. `cmd.exe /Q /c <command> 1> \\<host>\ADMIN$\__<epoch>.<rand> 2>&1`. The `1> \\...\ADMIN$\__...` redirect — stdout is written to a file on the remote admin share and read back over SMB. `/Q` (quiet) hides it further.
2. The **parent process**: `mmc.exe -Embedding` (DCOM) vs `wmiprvse.exe -secured -Embedding` (WMI). The field exists because Windows records *who created a process* — process ancestry is a trustworthy property the attacker cannot forge without a much more advanced technique.
3. `127.0.0.1` = the connection originated **on the local machine** (loopback): a proxy/relay, a local escalation, or the tool running locally. `10.0.2.16` = a **different machine** reached in over the network — genuine lateral movement, and it gives you the attacker's IP to pivot on.
4. **1102** (Security log cleared), or **104** in the System channel. The attacker **cannot** remove: events already forwarded to a SIEM/WEF collector, and the `1102` event itself — it is written *because* the log was cleared.
5. **The domain controller.** Impact and privilege matter more than volume; the DC is the credential store for the whole domain.

---

## Cheat sheet for this lab

```powershell
cd C:\hayabusa-demo

# Full scan (11–17 s)
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Lateral Movement" -o lm.csv -H lm.html -w

# The tool comparison
Import-Csv .\lm.csv | Where-Object RuleTitle -like '*Impacket*'     | Select-Object -First 1 -ExpandProperty Details
Import-Csv .\lm.csv | Where-Object RuleTitle -like '*CrackMapExec*' | Select-Object -First 1 -ExpandProperty Details
Import-Csv .\lm.csv | Where-Object RuleTitle -like '*PsExec*'       | Select-Object -First 2 -ExpandProperty Details

# Anti-forensics
Import-Csv .\lm.csv | Where-Object RuleTitle -eq 'Log Cleared' | Format-Table Timestamp, Computer, EventID
Import-Csv .\lm.csv | Where-Object RuleTitle -like '*RunMRU*'  | Group-Object Computer

# Pipes
Import-Csv .\lm.csv | Where-Object RuleTitle -match 'Named Pipe' | Format-Table Timestamp, RuleTitle, Level

# Hosts and logons
.\hayabusa.exe computer-metrics -d ".\EVTX-ATTACK-SAMPLES\Lateral Movement"
.\hayabusa.exe logon-summary    -d ".\EVTX-ATTACK-SAMPLES\Lateral Movement" -o lm-logon

# MITRE columns
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Lateral Movement" -p verbose -o lm-mitre.csv -w

# Hunting across the folder (keyword search is CASE-SENSITIVE: add -i to ignore case)
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES\Lateral Movement" -k 'ADMIN$' -k wmiprvse -k PSEXESVC
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES\Lateral Movement" -k psexesvc -i
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES\Lateral Movement" -r 'ADMIN\$.*__\d+'

# One technique, one file
.\hayabusa.exe dfir-timeline -f ".\EVTX-ATTACK-SAMPLES\Lateral Movement\LM_wmiexec_impacket_sysmon_whoami.evtx" -o wmiexec.csv -w
```

---

## Expected results reference

| Query | Expected |
|---|---|
| `dfir-timeline` on this folder | 47 files, **1,238 detections / 89 unique**, 11–17 s |
| Severity split | crit **1** · high **92** · med **54** · low **53** · info **1,038** |
| "HackTool - Potential Impacket Lateral Movement Activity" | 9 hits |
| "HackTool - CrackMapExec Execution Patterns" | 6 hits |
| "Suspicious Redirection to Local Admin Share" | 6 hits |
| "Suspicious PsExec Execution" | 3 hits |
| "First Time Seen Remote Named Pipe" | 5 hits |
| "Log Cleared" | 5 hits (Event ID 1102) |
| "RunMRU Registry Key Deletion" | 21 hits, all `MSEDGEWIN10` |
| critical | 1 — "Malicious Named Pipe Created", `IEWIN7`, Sysmon 18 |
| `computer-metrics` | 11 computers; top `PC01.example.corp` (910) |
| `logon-summary` | 986 records, **0 failed logons** |

MITRE ATT&CK coverage in this folder:

| Detection | Tags |
|---|---|
| HackTool - Potential Impacket Lateral Movement Activity | `Exec` `LatMov` · **T1047** · **T1021.003** |
| HackTool - CrackMapExec Execution Patterns | `PrivEsc` `Persis` `Exec` · **T1047** **T1053** **T1059.003** **T1059.001** · S0106 |
| First Time Seen Remote Named Pipe | `LatMov` · **T1021.002** |
| Suspicious PsExec Execution | `LatMov` · **T1021.002** |
| MMC Spawning Windows Shell | `LatMov` · **T1021.003** |
| Suspicious Redirection to Local Admin Share | `Exfil` · **T1048** |
| Malicious Named Pipe Created | `PrivEsc` `Stealth` · **T1055** |
| Log Cleared | `Stealth` · **T1070.001** |
| RunMRU Registry Key Deletion | `Stealth` · **T1070.003** |

---

## Gotchas specific to this lab

| Symptom | Cause | Fix |
|---|---|---|
| Banner prints, then no CSV | ran from inside the tactic folder, `rules` not found | `cd` to the demo root |
| Windows PowerShell mangles `ADMIN$` | `$` starts a variable in double quotes | single-quote the pattern: `-r 'ADMIN\$\__\d+'` |
| 1,038 of 1,238 rows are `info` | this folder logs every descriptive event | filter `Level -in @('crit','high')` |
| Impacket and CrackMapExec look identical | by design — compare `ParentCmdline`, not `Cmdline` | see Step 3 |
| `-k a,b` returns nothing | comma becomes part of the search string | repeat the flag: `-k 'ADMIN$' -k wmiprvse` |
| `search` finds nothing for a keyword you can see in the CSV | keyword search is **case-sensitive** by default | add `-i`, or match the real casing (`PSEXESVC`, `ADMIN$`) |
| regex with `\_` returns 0 findings | `\_` is not a valid escape in Hayabusa's regex engine | use `.*` or `[0-9]+` instead |

---

## Files worth opening live (if a student asks "show me one")

| File | Shows |
|---|---|
| `LM_wmiexec_impacket_sysmon_whoami.evtx` | Canonical Impacket WMI exec |
| `LM_impacket_docmexec_mmc_sysmon_01.evtx` | Impacket over DCOM via MMC |
| `LM_renamed_psexecsvc_5145.evtx` | PsExec with a **renamed** service binary — name-based detection fails |
| `smb_bi_auth_conn_spoolsample.evtx` | Printer Bug / spooler coercion relay |
| `LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx` | LethalHTA: DCOM spawning `mshta` |
| `LM_xp_cmdshell_MSSQL_Events.evtx` | Lateral movement through SQL Server |
| `LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx` | How little WinRM logs on the target — a real blind spot |

---

**Previous:** [Privilege Escalation lab](<../Privilege Escalation/README.md>) · **Main guide:** [../../README.md](../../README.md)
