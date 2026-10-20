# Lab 2 — Privilege Escalation: "UAC Is Not a Security Boundary"

**Duration:** 20 minutes
**Data:** 66 `.evtx` files recorded while attackers escalated from a normal user to `NT AUTHORITY\SYSTEM`
**Tool:** Hayabusa v4.2.0 (in the demo root, two levels up)

> This is a standalone lab. The main instructor guide is [../../README.md](../../README.md).
> A follow-on lab is [Lateral Movement](<../Lateral Movement/README.md>).

---

## Learning objectives

By the end of 20 minutes students should be able to:

1. Explain the difference between **UAC bypass** and a **privilege escalation vulnerability** — and why Microsoft says UAC is *not* a security boundary.
2. Recognise the UACMe tool family in Sysmon Event ID 1 and map it to **T1548.002**.
3. Recognise the **Potato** attack family (SeImpersonate abuse) and explain the 30-second version of how it works.
4. Use `computer-metrics` to find the affected host without reading logs.
5. Answer: *if a user only has a standard account, how did the attacker become SYSTEM?*

---

## Before you start

Run everything from the **demo root** (the folder containing `hayabusa.exe`). All output files are written there.

```powershell
cd C:\hayabusa-demo
```

> **Important:** if you `cd` into a tactic folder and run `..\..\hayabusa.exe`, Hayabusa cannot find its `rules` folder and produces **no output at all** (no error, just a banner). Always run from the demo root, or pass `-r ..\..\rules -c ..\..\rules\config` explicitly.

Optional pre-flight (should take ~13 s):

```powershell
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Privilege Escalation" -o pe.csv -w
```

Then delete `pe.csv` before class so the demo starts clean.

---

## Demo timeline

| # | Step | Time |
|---|---|---|
| 1 | Set the scene: the UAC dialog is a lie | 2 min |
| 2 | Run the scan | 3 min |
| 3 | UACMe 22 — the tool that opens the door | 4 min |
| 4 | TrustedPath bypass — the critical finding | 3 min |
| 5 | Potato attacks — SeImpersonate → SYSTEM | 4 min |
| 6 | Worksheet + answers | 4 min |

---

## Step 1 — Set the scene (2 min)

Ask the class:

> "A user is a **standard user**, no admin rights. They click *Yes* on a UAC prompt. What did they just grant?"

The expected answer — and the one to correct if wrong — is:

> UAC is a **consent** boundary, not a **security** boundary. A standard user saying *Yes* implies **consent to use admin credentials they already possess**. On a machine where the user is a *local administrator running with a filtered token*, an attacker who can **bypass the consent prompt** gains full admin **without ever showing a dialog**. That is a UAC bypass, not an exploit.

That distinction is the whole lab: this folder contains **35 files covering UAC bypasses**, including **21 distinct UACMe method numbers** (22–64), all abusing legitimate Windows binaries.

---

## Step 2 — Run the scan (3 min)

```powershell
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Privilege Escalation" -o pe.csv -H pe.html -w
```

Measured output (~13 seconds):

```
Total event log files: 66
Total detection rules: 4,674
Total | Unique detections: 831 | 138
Total | Unique critical detections: 3
Total | Unique high detections:   149
```

> **Say this:** "138 unique behaviours across 66 log files. Notice there is **no single 'privilege escalation' event ID** in Windows — that is why detection rules exist. The operating system faithfully logs the *symptoms* (a process launched, a registry key written, a pipe created) and we infer the *intent*."

---

## Step 3 — UACMe 22 (4 min)

```powershell
Import-Csv .\pe.csv | Where-Object RuleTitle -like '*Akagi*' |
    Select-Object Timestamp, Computer, Level | Format-Table -AutoSize
```

**Expect 22 detections** — 20 on `MSEDGEWIN10` and 2 on `DESKTOP-NTSSLJD` — all **high**.

Now look at what the rule actually matched:

```powershell
Import-Csv .\pe.csv | Where-Object RuleTitle -like '*Akagi*' | Select-Object -First 1 -ExpandProperty Details
```

Real evidence:

```
Cmdline: UACME.exe 22
Proc:    C:\Users\IEUser\Desktop\UACME.exe
User:    MSEDGEWIN10\IEUser
ParentCmdline: "C:\Windows\system32\cmd.exe"
Product: UACMe      Company: Hazardous Environments
IMPHASH: B6789EDFE23DDA911A
```

Point out three separate detection opportunities in **one** event:

| Evidence | What it proves |
|---|---|
| Binary named `UACME.exe` on the **Desktop** | User-writable location — real admin tools do not live here |
| `Company: Hazardous Environments` | The author's joke, but also a strong signature |
| `IMPHASH B6789EDFE23DDA911A` | Survives renaming — this is what the **critical** "Hacktool Execution - Imphash" rule keys on |

> **Say this:** "The `22` in `UACME.exe 22` is the **method number** — the attacker is walking through every known bypass. The other 20 `Sysmon_UACME_*.evtx` files in this folder cover methods 23 through 64. One tool, dozens of techniques, and Hayabusa recognises them by *behaviour*, not by file name."

MITRE: **T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control**.

---

## Step 4 — TrustedPath bypass, the critical finding (3 min)

```powershell
Import-Csv .\pe.csv | Where-Object Level -eq 'crit' |
    Select-Object Timestamp, RuleTitle, Computer, EventID | Format-Table -AutoSize
```

Three critical detections, including **two "TrustedPath UAC Bypass Pattern"** on `MSEDGEWIN10` (2019-07-28, Sysmon 1).

Explain the trick in plain language:

> Windows shows the UAC dialog on the **Secure Desktop**, and it only trusts binaries in `C:\Windows\System32`. If malware can get Windows to launch a *trusted*-looking binary that it controls, the dialog either never appears or auto-approves — because Windows believes the process is already privileged.

```powershell
# See every bypass technique the dataset contains
Import-Csv .\pe.csv | Where-Object { $_.Level -in @('crit','high') } |
    Group-Object RuleTitle | Sort-Object Count -Descending |
    Select-Object Count, Name -First 12 | Format-Table -AutoSize
```

Expected top rules:

| Rule | Count | Level |
|---|---|---|
| HackTool - UACMe Akagi Execution | 22 | high |
| Cab File Extraction Via Wusa.EXE | 16 | high |
| Proc Exec (Sysmon Alert) | 8 | high |
| Network Connection Initiated Via Notepad.EXE | 7 | high |

> **Say this:** "Look at the second one. `wusa.exe` is the *Windows Update Standalone Installer* — a signed Microsoft binary. The command line here is `wusa.exe C:\...\Temp\uf3huvkczgk.tmp /extract:C:\Windows /quiet`, with a **PowerShell parent**. A signed system binary being used as a file-extraction service to drop a payload into `C:\Windows`. That is living-off-the-land in one line."

---

## Step 5 — Potato attacks: SeImpersonate → SYSTEM (4 min)

This is the most important concept in the lab for real-world work.

```powershell
Import-Csv .\pe.csv | Where-Object RuleTitle -match 'Notepad|Potato' |
    Select-Object Timestamp, RuleTitle, Computer, Level | Format-Table -AutoSize
```

Real evidence — the single most instructive row in the dataset:

```
Proc:  C:\Windows\System32\notepad.exe
User:  IIS APPPOOL\DefaultAppPool
TgtIP: 127.0.0.1   TgtPort: 135
EventID: 3 (network connection)
```

> **Say this:** "`notepad.exe` does not make network connections. This one is running as the **web server's application pool identity** — which means it was spawned by a **webshell** — and it is connecting to **port 135**, the RPC endpoint mapper. That combination is the signature of a **Potato attack**: the attacker forces a privileged service to authenticate to a named pipe *they* control, then impersonates the SYSTEM token that arrives."

Walk the family:

| Detection | Count | Technique | The idea |
|---|---|---|---|
| Network Connection Initiated Via Notepad.EXE | 7 | T1055 | RPC coercion from a webshell |
| HackTool - EfsPotato Named Pipe Creation | 6 | T1055 | EFS RPC coerced to a controlled pipe |
| RottenPotato Like Attack Pattern | 1 | T1557.001 | NTLM relay to localhost |
| Windows Spooler Service Suspicious Binary Load | 2 | T1574 | Print Spooler as the privileged service |

Show the pipe evidence:

```powershell
Import-Csv .\pe.csv | Where-Object RuleTitle -like '*EfsPotato*' | Select-Object -First 1 -ExpandProperty Details
```

```
Pipe: \dd4c18dc-bff6-42ce-b707-62c114b84291\pipe\srvsvc
Proc: c:\temp\EfsPotato.exe
```

> **Say this:** "A GUID-named pipe is a pipe the attacker created. `srvsvc` is a privileged Windows service. When a *privileged* service connects to an *attacker's* pipe, the attacker controls the impersonation. This is why **SeImpersonatePrivilege is equivalent to SYSTEM** on a server — and why IIS app pools, MSSQL and scheduled tasks are so dangerous."

Why this matters operationally: any service account holding `SeImpersonate` (IIS, MSSQL, most service accounts) is one Potato away from SYSTEM.

---

## Step 6 — Which host? (fast, part of the worksheet)

```powershell
.\hayabusa.exe computer-metrics -d ".\EVTX-ATTACK-SAMPLES\Privilege Escalation"
```

```
DESKTOP-NTSSLJD                 530
MSEDGEWIN10                     384
IEWIN7                          130
LAPTOP-JU4M3I0E                  42
01566s-win16-ir.threebeesco.com  18
...
Total computers: 11
```

`DESKTOP-NTSSLJD` is the top host in this folder — a different victim than the one in the Credential Access lab. Good reminder that each sample set is its own incident.

Also worth 10 seconds:

```powershell
.\hayabusa.exe logon-summary -d ".\EVTX-ATTACK-SAMPLES\Privilege Escalation" -o pe-logon
```

66 logon records, **zero failed logons** — again, no brute force. The attacker is local.

---

## Worksheet (hand out during Step 6)

1. Which user account launched `UACME.exe`, and what does that tell you about the attacker's starting privileges?
2. Why is `IMPHASH` more useful than a file name for detecting `UACME.exe`?
3. `notepad.exe` connected to `127.0.0.1:135`. Give **two** reasons this is suspicious.
4. A service account runs your web app. It holds `SeImpersonatePrivilege`. Your manager says "it's only a web app, it has no admin rights." Are they right?
5. The dataset contains detections for `EfsPotato`, `RoguePotato`, `JuicyPotato` and `RottenPotato`. If you could only block **one** underlying capability to stop all four, what would it be?

### Answer key

1. `MSEDGEWIN10\IEUser` — an ordinary interactive user. The escalation started from a **standard, non-admin** context, which is exactly why a UAC bypass was needed.
2. A file name is one string the attacker controls and can change in one second. An **import hash** is derived from the PE import table — it changes only if the *code* changes, which is far more expensive. `UACME.exe` here hashes to `B6789EDFE23DDA911A`.
3. (a) `notepad.exe` is a text editor; it has no legitimate reason to open a network connection. (b) Port **135/RPC** is what a Potato attack coerces — and the process was running as `IIS APPPOOL\DefaultAppPool`, meaning it came from a web shell.
4. **No.** `SeImpersonatePrivilege` lets the account impersonate any token that connects to it. Combined with RPC coercion (Potato) that is a reliable path to `NT AUTHORITY\SYSTEM` — no admin group membership required. This is why service accounts must be treated as privileged.
5. Remove **`SeImpersonatePrivilege`** from the account (or run it under a gMSA / with the privilege stripped). All four Potatoes depend on coercing an authentication and impersonating the resulting token.

---

## Cheat sheet for this lab

```powershell
cd C:\hayabusa-demo

# Full scan (13 s)
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Privilege Escalation" -o pe.csv -H pe.html -w

# UACMe evidence
Import-Csv .\pe.csv | Where-Object RuleTitle -like '*Akagi*' | Format-Table Timestamp, Computer, Level
Import-Csv .\pe.csv | Where-Object RuleTitle -like '*Akagi*' | Select-Object -First 1 -ExpandProperty Details

# Critical only
Import-Csv .\pe.csv | Where-Object Level -eq 'crit' | Format-Table Timestamp, RuleTitle, Computer, EventID

# Potato family
Import-Csv .\pe.csv | Where-Object RuleTitle -match 'Notepad|Potato' | Format-Table Timestamp, RuleTitle, Level

# Hosts
.\hayabusa.exe computer-metrics -d ".\EVTX-ATTACK-SAMPLES\Privilege Escalation"

# MITRE columns
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Privilege Escalation" -p verbose -o pe-mitre.csv -w
Import-Csv .\pe-mitre.csv | Where-Object Level -eq 'crit' | Format-List RuleTitle, MitreTactics, MitreTags

# One technique, one file
.\hayabusa.exe dfir-timeline -f ".\EVTX-ATTACK-SAMPLES\Privilege Escalation\Sysmon_UACME_22.evtx" -o uacme22.csv -w

# Hunting
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES\Privilege Escalation" -k UACME -k Potato -k wusa
```

---

## Expected results reference

| Query | Expected |
|---|---|
| `dfir-timeline` on this folder | 66 files, **831 detections / 138 unique**, ~13 s |
| Severity split | crit **3** · high **149** · (medium/low/info remainder) |
| "HackTool - UACMe Akagi Execution" | 22 hits (20 `MSEDGEWIN10` + 2 `DESKTOP-NTSSLJD`), all high |
| "TrustedPath UAC Bypass Pattern" | 2 hits, **critical**, 2019-07-28 |
| "Cab File Extraction Via Wusa.EXE" | 16 hits |
| "Network Connection Initiated Via Notepad.EXE" | 7 hits, user `IIS APPPOOL\DefaultAppPool` |
| "HackTool - EfsPotato Named Pipe Creation" | 6 hits |
| `computer-metrics` | 11 computers; top `DESKTOP-NTSSLJD` (530), `MSEDGEWIN10` (384), `IEWIN7` (130) |
| `logon-summary` | 66 records, **0 failed logons** |
| `-p verbose` | 831 detections; 138 unique |

MITRE ATT&CK coverage in this folder:

| Detection | Tags |
|---|---|
| HackTool - UACMe Akagi Execution | `PrivEsc` · **T1548.002** |
| TrustedPath UAC Bypass Pattern | `PrivEsc` · **T1548.002** |
| Network Connection Initiated Via Notepad.EXE | `PrivEsc` `C2` `Exec` `Stealth` · **T1055** |
| HackTool - EfsPotato Named Pipe Creation | `PrivEsc` `Stealth` · **T1055** |
| RottenPotato Like Attack Pattern | `Collect` `PrivEsc` `CredAccess` · **T1557.001** |
| Windows Spooler Service Suspicious Binary Load | `Persis` `PrivEsc` `Exec` `Stealth` · **T1574** |
| Hacktool Execution - Imphash | `CredAccess` `ResDev` · **T1588.002** / **T1003** |

---

## Gotchas specific to this lab

| Symptom | Cause | Fix |
|---|---|---|
| Banner prints, then nothing, no CSV | launched from inside the tactic folder, so `rules` was not found | `cd` to the demo root first |
| `Cab File Extraction Via Wusa.EXE` appears **twice** per event | two similar rules fire on the same behaviour | expected; count events, not rule names |
| Very few `crit` results | these samples are technique-focused, not campaign-focused | use `high` as the working level here |
| `.etl`-style files appear in listings | this folder is `.evtx` only; other folders have ETL traces | Hayabusa skips non-`.evtx` |

---

## Files worth opening live (if a student asks "show me one")

| File | Shows |
|---|---|
| `Sysmon_UACME_22.evtx` | The canonical UACMe run, one method |
| `Sysmon_13_1_UACBypass_SDCLTBypass.evtx` | Registry hijack style bypass |
| `privesc_rotten_potato_from_webshell_metasploit_sysmon_1_8_3.evtx` | Full webshell → Potato chain |
| `EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx` | Named-pipe evidence of SeImpersonate abuse |
| `win10_4703_SeDebugPrivilege_enabled.evtx` | The privilege being granted, in Security log |
| `UACME_61_Changepk.evtx` | A different bypass family entirely |

---

**Next:** [Lateral Movement lab](<../Lateral Movement/README.md>) — the attacker now has SYSTEM on one host. What do they do with it?
