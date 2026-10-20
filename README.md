# Windows Threat Hunting — Live Demo Guide

**Tool:** [Hayabusa](https://github.com/Yamato-Security/hayabusa) v4.2.0 — "Autumn Release" (13 Oct 2026), by Yamato Security
**Data:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) — 278 real attack log files
**Audience:** Students new to DFIR / blue team / SOC work
**Total time:** ~25–30 minutes

> **Start here:** Section **1a** explains what the tool is, Section **1b** gives its history and the licence context, and Section **6a** is the complete command reference. Jump to Section **6** if you just want the demo script.

---

## 1. The one-sentence pitch

> "Windows already records the attack — every process launch, every logon, every LSASS access. The problem is that nobody can read 46 MB of raw event logs. Hayabusa reads them for you and tells you *which* events were malicious, *how* dangerous they are, and *which* MITRE ATT&CK technique was used."

Two separate things are needed, and students should understand why:

| Component | Role | Analogy |
|---|---|---|
| `hayabusa.exe` + `rules/` | The **detector** — the engine + 4,674 detection rules | The video player |
| `EVTX-ATTACK-SAMPLES/` | The **data** — raw `.evtx` logs recorded during real attacks | The movie file |

A player with no movie is useless. A movie with no player means staring at raw XML.

---

## 1a. The tool: what Hayabusa actually is

> **Say this before you touch the keyboard:** *"Hayabusa is a Windows event log forensics timeline generator and threat hunting tool, written in Rust by a Japanese security company called Yamato Security. The name means 'peregrine falcon' — a bird that hunts other birds. The falcon hunts in your event logs."*

### The one-line definition

> **Hayabusa reads Windows `.evtx` event logs natively, matches every event against ~4,700 community-written detection rules, and outputs one consolidated, severity-ranked timeline.**

Everything else in this guide is a detail of that sentence.

### Verified facts about the binary you are running

| Property | Value | How it was confirmed |
|---|---|---|
| File | `hayabusa.exe` | 11.2 MB, no installer |
| Version | **4.2.0** ("Autumn Release") | `FileVersion` / `ProductVersion` in the PE header |
| Vendor | **Yamato Security** | `CompanyName` in the PE header |
| Description | `Hayabusa - Windows Event Log Analyzer` | `FileDescription` in the PE header |
| Licence | **GNU AGPL v3** | upstream repo |
| Language | **Rust** | upstream repo, `language: Rust` |
| Released | **13 Oct 2026** | upstream release `v4.2.0` |
| Repo created | **18 Sep 2020** | upstream repo `created_at` |
| Stars / Forks | **~3,400 / 300** | upstream repo |
| Docs | [yamato-security.github.io/hayabusa](https://yamato-security.github.io/hayabusa/) — **15 languages** | upstream |

Confirm it yourself:

```powershell
(Get-Item .\hayabusa.exe).VersionInfo | Format-List FileVersion, CompanyName, FileDescription
.\hayabusa.exe help
```

> **Teaching note:** the `FileDescription` says *"Windows Event Log Analyzer"*, not "antivirus" and not "SIEM". This is a **forensic analysis tool** — it reads evidence after the fact. It does not block anything, it does not sit on your network. Students who think "security tool = prevention tool" need this corrected early.

### Why "Hayabusa"?

隼 (*hayabusa*) is the Japanese peregrine falcon — the fastest animal in the world in a dive. Yamato Security names its tools after fast birds of prey. The metaphor is the **speed** of native `.evtx` parsing versus XML conversion.

### Why Rust?

This is not trivia — it is the reason the tool is fast and safe on a production box:

- **Performance.** Rust compiles to native code with no runtime, so Hayabusa parses millions of records multi-threaded without the overhead of a managed language. The GitHub repo even ships a [`rust-reportcard`](https://rust-reportcard.xuri.me/report/github.com/Yamato-Security/hayabusa) badge.
- **Memory safety.** Rust prevents use-after-free and buffer overflows at compile time. A DFIR tool that gets fed thousands of attacker-controlled log files is exactly the kind of program where memory-safety bugs would be a serious problem. The upstream README calls it *"memory-safe Rust"*.

> **Say this:** "A forensic parser reads files that an attacker may have influenced. Writing that in a language that cannot have memory-corruption bugs is a genuine security decision, not a fashion choice."

---

## 1b. History and context

### The lineage: three separate projects that Hayabusa stitches together

| Layer | Project | What it contributes | Licence |
|---|---|---|---|
| **Engine** | Hayabusa | The Rust parser, matcher and timeline generator | AGPL v3 |
| **Detection logic** | [Sigma](https://github.com/SigmaHQ/sigma) | ~4,800 rules in a vendor-neutral YAML format | DRL 1.1 |
| **Rule curation** | [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) | Tunings, exclusions, proven-rule list, level adjustments | AGPL v3 |
| **Test data** | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | 278 real attack `.evtx` files, grouped by ATT&CK tactic | GPL |

**The crucial point:** Hayabusa did **not** invent its own detections. It implemented the **Sigma** standard, so the *same* rule written by a researcher works in Hayabusa, in Elastic, in Splunk, and in every other Sigma-compatible tool. That is why the rules directory contains `rules\sigma\` (4,804 files) and `rules\hayabusa\` (196 native, non-Sigma rules).

> **Say this:** "Sigma is the shared language of detection engineering. One rule, written once, runs in every tool that speaks it. Hayabusa didn't invent the rules — it made them *fast*."

### Timeline

| When | What happened |
|---|---|
| **2017** | The oldest rule in your set: `win_alert_mimikatz_keywords.yml` by Florian Roth (Nextron Systems) and David ANDRE, dated **2017-01-10**. Mimikatz had just escaped into the wild and every vendor was writing their own keyword list. Sigma itself was founded around this era to stop the duplication. |
| **2017 → 2022** | The attack logs in this repo were captured. The earliest events in `Credential Access` are dated **2017**, the latest **2022** — a five-year archive of adversary simulation. |
| **18 Sep 2020** | **Hayabusa is created** as a public repo by Yamato Security. The problem it solves: Windows event logs are binary `.evtx`, and every tool that reads them converts to XML first — which is slow and lossy. |
| **2020 → 2022** | Rapid adoption. Sigma rule counts climb into the thousands. Hayabusa builds the **level-tuning** and **proven-rules** workflow that makes community rules usable in production. |
| **2022** | First major conference talks: **Black Hat Asia 2022 Arsenal**, **CODE BLUE 2022**, **SECCON 2023**, **Security MiniCamp Tokyo 2023**, **SANS DFIR Summit 2023**. |
| **2023 → 2024** | **BSides Tokyo 2024**, **Hack Fes 2024**, **HITCON 2024**, **SecTor 2024**. The tool moves from a specialist DFIR utility to a mainstream blue-team tool. |
| **2024 → 2025** | **SINCON Kampung Workshop 2025**, **Black Hat USA 2025 Arsenal** ("Windows Fast Forensics with Yamato Security's Hayabusa"), **CODE BLUE 2025**. |
| **2026** | **Black Hat USA 2026 Arsenal** — including *"Mecha-Hayabusa"*. **v4.1.0 "Suzumushi Release"** (12 Sep 2026), then **v4.2.0 "Autumn Release"** (13 Oct 2026) — the version in this folder. |

> **Teaching note:** the release names are traditional Japanese seasonal or nature terms. **Suzumushi** (鈴虫) is the bell cricket — a Japanese symbol of late summer. **Autumn** is the season. The naming convention means *v4.1 and v4.2 are the same season, adjacent releases* — you may see both cited.

### What changed in v4 — and why it will bite you

v4.0 was the **breaking-change** release. The single most important rename:

```
csv-timeline   →   dfir-timeline
```

> **⚠️ This is the #1 live-demo failure.** Every blog post, tutorial and AI-generated answer written before v4 says `csv-timeline`. Copy one into the terminal and you get:
> ```
> error: unrecognized subcommand 'csv-timeline'
> ```
> Always check `.\hayabusa.exe help` for the current command list.

Other v4-era changes worth knowing:

- **`-p verbose` profile** now includes `MitreTactics` / `MitreTags` — the MITRE ATT&CK mapping is a first-class output field.
- **`-a` and `-A` were split**: `-a` disables the *event channel filter*, `-A` disables the *rule* filter. Before v4 these were conflated.
- **Correlation rules** (3 in this set) allow one rule to reference another rule's output — the foundation for multi-step attack detection.

### The broader ecosystem — where Hayabusa sits

```
   Sigma rules (YAML)          hayabusa-rules (tuning)
          |                            |
          +------------+---------------+
                       |
                       v
              HAYABUSA (Rust engine)
                       |
     +---------+-------+-------+---------+---------+
     v         v       v       v         v         v
   CSV      JSON     JSONL    HTML    Timesketch  Elastic
                    (SIEM ingest)  (profile)  (profile)
```

- **Timesketch** — Google/MorESTaff's open-source timeline tool. Hayabusa ships `timesketch-minimal` and `timesketch-verbose` profiles so a scan can be loaded straight into it.
- **Elastic Stack** — the `json` / `jsonl` output is directly ingestible via Elastic Agent / Filebeat. SIEM handoff is one command, not an export hack.
- **Timeline Explorer** (Eric Zimmerman) — CSV opens natively.
- **Velociraptor** — for live-response collection across an enterprise; Hayabusa analyses what Velociraptor gathers.
- **Windows built-ins** — `Get-WinEvent` and Event Viewer. Hayabusa's entire value proposition is being **faster and more precise** than these.

> **Say this:** "Hayabusa does not replace your SIEM. It is the thing that turns raw Windows logs into something a SIEM can ingest — and it does it in seconds, on a laptop, with no server."

### The data set: EVTX-ATTACK-SAMPLES

Created by **Samir Bousseaden** (`@sbousseaden`), who is also a Hayabusa rule contributor (you will see his name in the rule-authors table in Step 3). He captured these logs while running real adversary simulations and Atomic Red Team tests, then published them so defenders can practise without needing a malware lab or violating anyone's handling policy.

That is why the folder is organised by **ATT&CK tactic** rather than by date or by tool — it is a *curriculum*, not a random dump. Each subfolder is a chapter:

| Folder | Files | ATT&CK tactic |
|---|---|---|
| `Privilege Escalation` | 66 | Privilege Escalation |
| `Lateral Movement` | 47 | Lateral Movement |
| `Credential Access` | 39 | Credential Access ← **this lab** |
| `Defense Evasion` | 36 | Defense Evasion |
| `Execution` | 34 | Execution |
| `Persistence` | 22 | Persistence |
| `Discovery` | 11 | Discovery |
| `AutomatedTestingTools` | 8 | Adversary simulation frameworks |
| `Other` | 8 | Misc. |
| `Command and Control` | 6 | Command and Control |
| **Total** | **278** | |

> **Say this:** "These are real attack logs, not synthetic ones. A synthetic log is a clean, tidy, idealised version — real logs have gaps, duplicate records, eight different clock formats and unrelated noise mixed in. Training on synthetic logs teaches you to expect clean data, and then real incidents surprise you."

### The rule corpus, in detail

Your `rules\` folder — verified contents:

```
rules\
├── sigma\          4,804 .yml   ← the Sigma community rules
│   ├── builtin\               ← generic Windows detections
│   └── sysmon\                ← Sysmon-specific detections
├── hayabusa\        196 .yml   ← Hayabusa-native rules (non-Sigma features)
└── config\            17 files ← the tuning layer (see below)
```

The `rules\config\` folder is the part students never see and analysts use daily:

| File | Purpose |
|---|---|
| `proven_rules.txt` | **1,277** rule IDs vetted as low-false-positive. Load these with `-P` for production. |
| `noisy_rules.txt` | 13 rules that fire too often to be useful by default. |
| `exclude_rules.txt` | 37 rules disabled entirely. |
| `level_tuning.txt` | Per-rule severity overrides — e.g. *"Mimikatz DC Sync"* raised `high` → `critical`. |
| `pivot_keywords.txt` | Seed list for the `pivot-keywords-list` hunt. |
| `channel_eid_info.txt` | Event ID → human description lookup (31 KB). |
| `windows_versions.csv` | Windows build → version map. |
| `opening_messages.txt` / `closing_messages.txt` | The ASCII art and the **50 Japanese proverbs** printed at exit. |
| `default_details.txt`, `eventkey_alias.txt`, `generic_abbreviations.txt`, `provider_abbreviations.txt`, `channel_abbreviations.txt`, `geoip_field_mapping.yaml`, `windash_characters.txt`, `target_event_IDs.txt` | Field mapping and display formatting. |

> **Say this:** "The `level_tuning.txt` file is the difference between a noisy tool and a usable one. A rule author says 'this is high severity'. A defender who knows their environment says 'no, for us that's critical'. The tool lets the *defender* have the last word, per rule, without forking the rules."

**Provenance and licensing — important for a corporate environment:**

| Component | Licence | Note |
|---|---|---|
| Hayabusa engine | **AGPL v3** | Strong copyleft — modifications must be published. Check with legal before embedding. |
| Sigma rules | **DRL 1.1** | Sigma's own Detection Rule Licence. |
| EVTX-ATTACK-SAMPLES | **GPL** | The logs themselves. |

> **⚠️ Do not skip this.** AGPL v3 is the licence that makes corporate lawyers nervous. If you plan to run Hayabusa *as a service* or embed it in a product, the AGPL network-use clause may oblige you to release your source. Running it as a standalone analyst tool on logs you already own is fine. This is a legitimate question to raise in class — and it is the same question every open-source security tool attracts.

### The small print that makes it feel like a Japanese product

Every Hayabusa run prints a **banner** at the start and a **Japanese proverb** at the end:

```
┏┓ ┏┳━━━┳┓  ┏┳━━━┳━━┓┏┓ ┏┳━━━┳━━━┓
┃┃ ┃┃┏━┓┃┗┓┏┛┃┏━┓┃┏┓┃┃┃ ┃┃┏━┓┃┏━┓┃
   by Yamato Security
Giving you the Windows event logs you've always wanted~
```

```
Closing: 平常心是道 - Heijoushin Kore Dou - An ordinary mind is the way.
```

There are **50** of them in `closing_messages.txt`. Seen in this session: `無念無想 (Munen Musou)`, `百聞は一見に如かず`, `風流韻事`, `不動心`, `平常心是道`, `一難去ってまた一難`.

> **Say this:** "It prints a proverb instead of 'Done'. Same words every time, but there are fifty, and each one is a genuinely appropriate sentiment for the task. It tells you the author is Japanese before you ever see the docs." *(And: "It's a nice touch, but it is **not** an error. If a student thinks it is, tell them to scroll up and read the actual results.")*

---

## 2. What is in this folder

```
hayabusa-demo\
├── hayabusa.exe          <- Hayabusa v4.2.0 (Windows x64 binary, no install needed)
├── rules\                <- 5,096 rule files (5,000 .yml; 4,674 load during a scan) + rules\config\
├── config\               <- report templates, severity colours, output profiles
└── EVTX-ATTACK-SAMPLES\  <- 278 .evtx files grouped by MITRE ATT&CK tactic
    ├── Credential Access\      (39 files)  <- demo target for this lab
    ├── Privilege Escalation\   (66 files)  <- Lab 2
    ├── Lateral Movement\       (47 files)  <- Lab 3
    ├── Defense Evasion\        (36 files)
    ├── Execution\              (34 files)
    ├── Persistence\            (22 files)
    ├── Discovery\              (11 files)
    ├── AutomatedTestingTools\  (8 files)
    ├── Other\                   (8 files)
    └── Command and Control\     (6 files)
```

> The tree shows **278** `.evtx` files total. The `Credential Access` folder holds 40 files but only 39 are `.evtx` — the extra one is an `.etl` trace, which Hayabusa skips.

**Do not move `hayabusa.exe` out of this folder.** It looks for `.\rules` and `.\config` relative to itself.

---

## 3. Requirements

- Windows 10 / 11 or Windows Server (the binary is x64)
- PowerShell 5.1 or newer — **nothing to install**, no Python, no Rust, no internet needed
- Permission to read files in this folder (no admin required)

> **Location:** this kit is installed at **`C:\hayabusa-demo`** on local disk — deliberately *outside* OneDrive.
> Every command in this guide assumes you are in that folder:
>
> ```powershell
> cd C:\hayabusa-demo
> ```
>
> A copy also remains at `C:\Users\salag\OneDrive\Desktop\Threat`. Use the `C:\hayabusa-demo` copy for teaching — it avoids cloud-sync stalls, and it is the path all three lab guides reference.
>
> **Why it matters:** measured on this machine, a *cold* first scan (right after copying, with Defender scanning the new files) took **195 seconds**. The same scan warm takes **12–15 seconds**. If you copy to a new location, run the scan once before class to warm the cache.
>
> **Keep `-C` on every command that writes a file.** Hayabusa refuses to overwrite an existing output unless `-C` (`--clobber`) is present, and it fails *before* scanning:
> `[ERROR] The file report.html already exists. Please specify a different filename or add the -C, --clobber option to overwrite.`
> Every command in this guide therefore includes `-C`. Without it, the second run of the demo dies on the error above.

---

## 4. Five minutes before class — pre-flight check

Run these so nothing surprises you in front of students.

```powershell
cd C:\hayabusa-demo
.\hayabusa.exe help
```

You should see the banner `Hayabusa v4.2.0 - Autumn Release` plus the command list.

```powershell
(Get-ChildItem .\EVTX-ATTACK-SAMPLES -Recurse -Filter *.evtx).Count
```

Expect `278`.

```powershell
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -o report.csv -H report.html -w -C
```

Expect `Saved file: report.csv` and about **12–15 seconds**. Then delete the outputs so the class starts clean:

```powershell
Remove-Item report.csv, report.html -Force
```

**If PowerShell refuses to run the exe** (`... is not recognized` / execution policy error), run it with an explicit path instead:

```powershell
& ".\hayabusa.exe" help
```

---

## 5. Demo timeline

| # | Step | Time | Purpose |
|---|---|---|---|
| 1 | Show the raw logs | 3 min | Establish the pain |
| 2 | Introduce the tool | 2 min | What Hayabusa is |
| 3 | The first scan | 2 min | The "wow" moment |
| 4 | Read the numbers | 3 min | Data reduction explained |
| 5 | Open the CSV | 4 min | What a detection looks like |
| 6 | Open the HTML report | 2 min | Deliverable for a manager |
| 7 | Filter to critical only | 2 min | Triage |
| 8 | Which machine was hacked? | 2 min | `computer-metrics` |
| 9 | Who logged in? | 3 min | `logon-summary` |
| 10 | Hunt for one keyword | 3 min | `search` = threat hunting |
| 11 | Map to MITRE ATT&CK | 3 min | `-p verbose` profile |
| 12 | Scale to the whole dataset | 2 min | 278 files in 14 s |
| 13 | Wrap-up + exercises | 2 min | Consolidation |

---

## 6. Step-by-step demo script

### Step 1 — Show the problem first (do NOT skip this)

Open a terminal in the demo folder:

```powershell
cd C:\hayabusa-demo
```

Ask the class: *"How many events are in this one log file?"*

```powershell
(Get-WinEvent -Path ".\EVTX-ATTACK-SAMPLES\Credential Access\CA_PetiPotam_etw_rpc_efsr_5_6.evtx").Count
```

**Output: `29109`** — in a **single** file.

> **Teaching note:** this command takes **30+ seconds** on this machine because `Get-WinEvent` parses the file through the Windows Event Log API. Hayabusa will read the same file natively in a fraction of a second. That contrast is worth calling out later — it is the whole reason Hayabusa exists.

Now show how little a raw event tells you:

```powershell
Get-WinEvent -Path ".\EVTX-ATTACK-SAMPLES\Credential Access\sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx" |
    Select-Object -First 1 | Format-List TimeCreated, Id, ProviderName, Message
```

**Output:** Event ID `10`, provider `Microsoft-Windows-Sysmon`, and `Message` is **empty**.

> **Say this:** "This is the most important event in the whole file — mimikatz reading LSASS memory to steal passwords — and the log gives us an Event ID and nothing else. No analyst can look at 29,109 lines and spot this. We need something that understands what Event ID 10 with `TgtProc: lsass.exe` *means*."

> **⚠️ Use `Select-Object -First 1`.** Without it, `Format-List` will render every event in the file and the terminal will scroll for minutes. The original `Get-WinEvent ... | Format-List` form also includes a `Message` property that PowerShell tries to resolve for every record — very slow on a 29,109-event file.

Optional: open it visually —

```powershell
Start-Process ".\EVTX-ATTACK-SAMPLES\Credential Access\CA_PetiPotam_etw_rpc_efsr_5_6.evtx"
```

---

### Step 2 — Introduce the tool

```powershell
.\hayabusa.exe help
```

Point out the two things that matter:

- **`dfir-timeline`** — the main command: scan logs, produce a timeline of detections.
- **`rules/`** — 5,096 rule files (Sigma + Hayabusa native) that define *what malicious looks like*.

> **Say this:** "Hayabusa is a *detection engine*. It reads the binary `.evtx` format directly — very fast — and converts Windows events into Sigma-compatible fields. The rules are community-maintained detection logic. The maker only has to write the rule once; the tool applies it to every log."

---

### Step 3 — The first scan (the wow moment)

```powershell
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -o report.csv -H report.html -w -C
```

Flags, in plain English:

| Flag | Meaning |
|---|---|
| `-d` | directory of `.evtx` files to scan |
| `-o` | write the timeline to this CSV |
| `-H` | also write a pretty HTML summary |
| `-w` | no-wizard: don't ask questions, just scan |
| `-C` | overwrite existing output files (**required** if the file already exists) |

> **⚠️ Two gotchas, both hit in live demos:**
> 1. In Hayabusa v4 the old command `csv-timeline` was **renamed to `dfir-timeline`**. If you or a student copy an older tutorial from the internet, it will fail with `unrecognized subcommand 'csv-timeline'`.
> 2. Without `-C`, any re-run fails with `The file report.html already exists` — Hayabusa checks *before* scanning, so you lose the run entirely.

---

#### What actually happens during those ~12–15 seconds

This is the part students never see explained, so walk them through it in order. The output prints five distinct phases:

**Phase 1 — Inventory the haystack**
```
Total event log files: 39
Total file size: 15.6 MiB
```

**Phase 2 — Load the rule book**
```
Excluded rules: 26
Noisy rules: 12 (Disabled)

Deprecated rules: 230 (4.92%) (Disabled)
Experimental rules: 380 (8.13%)
Stable rules: 245 (5.24%)
Test rules: 4,049 (86.63%)
Unsupported rules: 42 (0.90%) (Disabled)

Correlation rules: 3 (0.06%)
Correlation referenced rules: 3 (0.06%)

Expand rules: 19 (0.41%)
Enabled expand rules: 0 (0.00%)

Hayabusa rules: 183
Sigma rules: 4,490
hayabusa rules: 1
Total detection rules: 4,674
```
> **Say this:** "4,674 rules loaded, but only 4,508 fire after filtering — the tool itself discards rules that can't match the channels present in these logs. The rule book is bigger than the haystack; that's normal."

**Phase 3 — Channel filter**
```
Evtx files loaded after channel filter: 37
Detection rules enabled after channel filter: 4,508
```
Note it drops 39 → **37 files**. Two logs contained no channels any rule cares about. *"The tool only reads what it can act on."*

**Phase 4 — The scan itself** (the actual event-by-event matching, the fast part)

**Phase 5 — Results summary + artifacts**
```
Saved file: report.csv (494.6 KiB)
HTML report: report.html
Elapsed time: 00:00:12.348
```

> **Teaching tip:** the rule-authors table (Zach Mathis (31), Florian Roth (25), Samir Bousseaden (3)…) is a credibility prop. *"These aren't one person's rules. This is the community's detection knowledge, and it's versioned and auditable."*

---

#### The "wow" — and the one sentence to land it

The summary block that fills the screen with severity colours:

```
Events with hits / Total events: 216 / 329 (Data reduction: 113 events (34.35%))

Total | Unique detections: 392 | 99
Total | Unique emergency detections: 0 (0.00%) | 0 (0.00%)
Total | Unique critical detections: 8 (2.04%) | 6 (6.06%)
Total | Unique high detections: 76 (19.39%) | 29 (29.29%)
Total | Unique medium detections: 95 (24.23%) | 32 (32.32%)
Total | Unique low detections: 85 (21.68%) | 17 (17.17%)
Total | Unique informational detections: 128 (32.65%) | 15 (15.15%)

First timestamp: 2017-06-10 00:51:26.968 +05:30
Last timestamp:  2022-02-16 16:07:25.097 +05:30

First detection: 2019-03-18 00:39:41.328 +05:30
Last detection:  2022-02-16 16:07:20.934 +05:30
```

Plus three bonus panels students love:

- **Dates with most detections** → `critical: 2019-06-21 (4)`, `high: 2019-05-27 (24)`, `medium: 2019-03-25 (22)`
- **Top 5 computers by unique detections** → `critical: MSEDGEWIN10 (3), alice.insecurebank.local (2), DESKTOP-PIU87N6 (1)`
- **Top alerts panels** → e.g. `Top critical alerts: HackTool - Dumpert Process Dumper (3), Potential Credential Dumping Via LSASS (2)`

> ### 🎤 The punchline
> *"We just ran 4,674 detection rules over 39 files. 329 events went in. **392 rule hits** came out — more than the input, because one event can trip several rules. After de-duplication that is **99 unique detections**, and of those only **6 are critical**. An analyst does not read 329 events. An analyst reads 6. That is the entire value proposition of detection engineering."*

The **Top computers** panel is your second wow moment — it answers "which machine was hacked?" before Step 8 even runs. **Point at it.**

---

#### Why the numbers are bigger than the input (students always ask this)

`329 events → 392 detections` looks impossible until you explain the two columns:

- **Total detections (392)** = every rule × every matching event, counted with multiplicity
- **Unique detections (99)** = each *distinct detection* counted once

One `mimikatz` command line can match "Imphash", "Proc Exec", and "Credential Dumping" simultaneously → 3 hits, 1 event. Hence the summary's own wording: `216 / 329` — only **216 of 329 events** produced *any* hit at all.

---

#### Teaching tips for this step

1. **Don't explain anything while it runs.** Say: *"It's loading 4,674 rules and reading 39 files totalling 15.6 MB."* Let the coloured table land first. Silence is the effect.
2. **Contrast with Step 1.** Remind them one of those files holds **29,109 events** and that raw Sysmon Event ID 10 showed an **empty message**. Now the tool names that event: *"Potential Credential Dumping Via LSASS."*
3. **Point at the elapsed-time line** (`00:00:12`) — vs. the cold-cache first scan on this machine that took **195 seconds**. *"The tool is fast because it parses `.evtx` natively instead of converting to XML first."*
4. **Close the loop to MITRE.** The folder you're scanning is *literally named* `Credential Access` — one of the ATT&CK tactics. Hayabusa is telling you the same thing in a different vocabulary. (Step 11 makes this explicit with `-p verbose`.)

---

### Step 4 — Read the numbers out loud

Now that the scan in Step 3 has run, walk the class through the summary block **line by line**. This is the analytical payoff of Step 3.

```
Total event log files: 39
Total file size: 15.6 MiB
Total detection rules: 4,674
Events with hits / Total events: 216 / 329 (Data reduction: 113 events (34.35%))
Total | Unique detections: 392 | 99
Total | Unique critical detections: 8 (2.04%)  | 6 (6.06%)
Total | Unique high detections:     76 (19.39%) | 29 (29.29%)
Total | Unique medium detections:   95 (24.23%) | 32 (32.32%)
Total | Unique low detections:      85 (21.68%) | 17 (17.17%)
Total | Unique informational:      128 (32.65%) | 15 (15.15%)

First timestamp: 2017-06-10 00:51:26.968 +05:30
Last timestamp:  2022-02-16 16:07:25.097 +05:30

First detection: 2019-03-18 00:39:41.328 +05:30
Last detection:  2022-02-16 16:07:20.934 +05:30
```

Read the **First/Last timestamp** lines as a forensic result, not a technicality: *"The earliest event in this folder is from **2017**, the last from **2022**. This collection is a five-year archive of attacks, not a single incident."*

Also explain the severity model students will meet forever after:

| Level | Meaning | Action |
|---|---|---|
| 🔴 **critical** | Almost certainly malicious (credential dumping tool, ransomware) | Drop everything |
| 🟠 **high** | Strongly suspicious | Investigate today |
| 🟡 **medium** | Suspicious, could be legitimate admin work | Correlate |
| ⚪ **low** | Weak signal / context | Background noise |
| ℹ️ **info** | Descriptive, no judgement | Context only |

---

### Step 5 — Open the CSV and dissect one row

```powershell
Import-Csv .\report.csv | Where-Object Level -eq 'crit' |
    Select-Object Timestamp, RuleTitle, Computer, EventID |
    Format-Table -AutoSize
```

Real output from this dataset (all 8 critical detections):

```
Timestamp                      RuleTitle                                            Computer                 EventID
---------                      ---------                                            --------                -------
2020-09-11 17:40:22.398 +05:30 HackTool - Mimikatz Kirbi File Creation              MSEDGEWIN10              11
2021-04-23 03:39:25.389 +05:30 Hacktool Execution - Imphash                         MSEDGEWIN10              1
2019-06-21 13:05:37.329 +05:30 HackTool - Dumpert Process Dumper Default File       alice.insecurebank.local 11
2019-06-21 13:05:50.259 +05:30 HackTool - Dumpert Process Dumper Default File       alice.insecurebank.local 11
2019-06-21 13:05:50.729 +05:30 HackTool - Dumpert Process Dumper Default File       alice.insecurebank.local 11
2019-06-21 13:05:37.185 +05:30 HackTool - Dumpert Process Dumper Execution          alice.insecurebank.local 1
2020-09-28 18:17:36.215 +05:30 Potential Credential Dumping Via LSASS Process Clone DESKTOP-PIU87N6          1
2021-12-07 23:03:01.680 +05:30 Potential Credential Dumping Via LSASS Process Clone MSEDGEWIN10              4688
```

> **Teaching point:** all 8 critical hits collapse onto **3 hosts and 4 rules**. That is the incident. Three machines, a handful of techniques — not 29,109 events.
>
> Notice the timestamps cluster: `alice.insecurebank.local` fired **four times within 13 seconds** on 2019-06-21. That burst is a single attack chain — one tool doing several things, not four separate incidents.

Now show the full detail of a single detection:

```powershell
Import-Csv .\report.csv | Where-Object Level -eq 'crit' | Select-Object -First 1 | Format-List
```

Actual output — compare this to the empty `Message` from Step 1:

```
Timestamp      : 2020-09-11 17:40:22.398 +05:30
RuleTitle      : HackTool - Mimikatz Kirbi File Creation
Level          : crit
Computer       : MSEDGEWIN10
Channel        : Sysmon
EventID        : 11
RecordID       : 385052
Details        : Path: C:\Windows\System32\mimilsa.log ¦ Proc: C:\Windows\system32\lsass.exe ¦ PID: 640 ¦ PGUID: 747F3D96-672C-5F5B-0D00-00000000FC00
ExtraFieldInfo : CreationUtcTime: 2020-09-11 12:10:22.357 ¦ RuleName: - ¦ UtcTime: 2020-09-11 12:10:22.357
RuleID         : 67fb9539-c38a-ffdd-c78d-b4980c3692f5
```

> **Say this:** "One line of CSV tells us the host, the process, the file, and that the rule name is 'Mimikatz Kirbi'. The raw log gave us `Event ID 11` and an empty message. **That is the whole product in one comparison.**"

To see the details of *one specific* detection, filter on the rule title:

```powershell
Import-Csv .\report.csv |
    Where-Object { $_.RuleTitle -like "*LSASS Process Clone*" } |
    Select-Object -First 1 | Format-List
```

Explain the columns:

| Column | Why it matters |
|---|---|
| `Timestamp` | When it happened — foundation of a timeline |
| `RuleTitle` | What the detector thinks happened |
| `Level` | How confident/urgent |
| `Computer` | Which host — scoping the incident |
| `Channel` | Security / Sysmon / System — where the evidence lives |
| `EventID` | The Windows event that triggered it |
| `RecordID` | Exact record — lets you go back to the raw log |
| `Details` | Human-readable extraction (usernames, paths, command lines) |
| `ExtraFieldInfo` | Remaining parsed fields |
| `RuleID` | Which rule fired — auditable detection |

> **Say this:** "Notice we don't just get 'something happened'. We get *which host*, *which user*, *which process*, *which command line*. That is what you need to write an incident report."

**The `Level` column uses abbreviations, not full words.** Get this wrong and every filter silently returns nothing:

```
crit   (8)     high   (76)     med   (95)     low   (85)     info   (128)
```

```powershell
# ✅ correct
Import-Csv .\report.csv | Where-Object Level -eq 'crit'

# ❌ wrong - returns 0 rows, no error
Import-Csv .\report.csv | Where-Object Level -eq 'critical'
```

There is also no `emergency` level in this dataset (0 occurrences) — `config\level_color.txt` defines it as a valid level, but no rule in this rule set uses it. The levels actually present in the CSV are `crit`, `high`, `med`, `low`, and `info`.

**Check the value set before you write a filter:**

```powershell
Import-Csv .\report.csv | Group-Object Level | Select-Object Name, Count
```

```powershell
Import-Csv .\report.csv | Where-Object Level -eq 'crit' | Select-Object -First 1 | Format-List
```

This prints the full record — the single most useful thing to show, because it is the "before/after" of Step 1: raw Event ID 10 with an empty message, now resolved into a named technique, a host, a process and a command line.

---

### Step 6 — The HTML report (the manager deliverable)

```powershell
Start-Process .\report.html
```

Scroll through it: severity pie chart, per-computer breakdown, top rules. The file is **369 KB** and completely self-contained — no server, no internet.

> **Say this:** "This is what you hand to a manager or attach to a ticket. The CSV is for machines; the HTML is for humans."

The full-dataset version (`full-report.html`, Step 12) is **439 KB** — the size barely changes because the HTML embeds the charts, not the raw events. That is worth pointing out: *"the report scales with findings, not with log volume."*

---

### Step 7 — Triage: critical only

```powershell
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -m critical -o crit-only.csv -w -C
```

`-m critical` = minimum level, so **only** critical rules load.

```
Total detection rules: 217
Events with hits / Total events: 8 / 329 (Data reduction: 321 events (97.57%))
Total | Unique critical detections: 8 (100.00%) | 6 (100.00%)
Elapsed time: 00:00:02.821
```

Note the runtime dropped from ~15 s to **2.8 s** — fewer rules to match means less work.

> **Say this:** "97.57% of the data disappeared. One command turned a 329-event haystack into 8 alerts. In a real incident with millions of events, this is how you survive."

Then confirm the file is genuinely smaller — this is the number to put on a slide:

```powershell
Get-Item report.csv, crit-only.csv | Select-Object Name, Length
```

```
Name          Length
----          ------
report.csv    506495
crit-only.csv 5297
```

> **Say this:** "A 100× smaller file. Same 8 critical alerts, 1% of the size. That is triage."

---

### Step 8 — Which machine was compromised?

```powershell
.\hayabusa.exe computer-metrics -d ".\EVTX-ATTACK-SAMPLES\Credential Access"
```

Output (0.5 s):

```
Total computers: 9
LAPTOP-JU4M3I0E                 29,528 events
IEWIN7                          96 events
MSEDGEWIN10                     70 events
01566s-win16-ir.threebeesco.com 66 events
DC1.insecurebank.local          62 events
alice.insecurebank.local        15 events
PC04.example.corp               11 events
DESKTOP-PIU87N6                  4 events
2016dc.hqcorp.local              1 event
```

> **Say this:** "Before reading a single alert, you already know where to look. `IEWIN7` and `MSEDGEWIN10` are your noisiest hosts — and note `DC1` and `2016dc` are domain controllers, the crown jewels."

> ### ⚠️ The `LAPTOP-JU4M3I0E` trap — ask the class about this
> `LAPTOP-JU4M3I0E` has **29,528 events** — more than every other host combined — and it appears in **zero** critical alerts. A student will ask *"isn't that the compromised machine?"*
>
> **It is not.** Those 29,528 events are almost entirely routine noise from one long-running log source. Volume ≠ compromise. If you sort by event count and start investigating `LAPTOP-JU4M3I0E`, you will waste the whole session.
>
> **The correct ranking is the one from Step 3's "Top 5 computers with most unique detections" panel** — that is ranked by *detections*, not by events. `MSEDGEWIN10` leads the critical column with 3.
>
> This is the single most important lesson in the whole demo: **prioritise by severity, not by volume.**

---

### Step 9 — Who logged in? Who failed?

```powershell
.\hayabusa.exe logon-summary -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -o logon-summary -C
```

Two files are produced: `logon-summary-successful.csv` and `logon-summary-failed.csv`.

```
Total Event Records:  145
First Timestamp:  2017-06-10 00:51:26.968 +05:30
Last Timestamp:   2022-02-16 16:07:25.097 +05:30
Successful logon results: logon-summary-successful.csv (1.5 KiB)
Failed logon results: logon-summary-failed.csv (312 B)
```

```powershell
Import-Csv .\logon-summary-successful.csv | Format-Table -AutoSize
Import-Csv .\logon-summary-failed.csv     | Format-Table -AutoSize
```

Successful logons — 9 rows:

```
Count  Target Account        Target Domain       Target Computer
-----  --------------        -------------       --------------
10     01566S-WIN16-IR$      THREEBEESCO.COM
2      ANONYMOUS LOGON       NT AUTHORITY
2      IEUser                MSEDGEWIN10
1      02694W-WIN10$         THREEBEESCO.COM
1      Administrator         3B
1      IEUser                MSEDGEWIN10
1      SYSTEM                NT AUTHORITY
1      samir                 3B
1      samir                 3B
```

Failed logons — 1 row:

```
Count  Target Account  Target Domain  Target Computer
-----  --------------  -------------  ---------------
1      IEUser          MSEDGEWIN10    MSEDGEWIN10
```

Teaching points from the real output:

- `ANONYMOUS LOGON` succeeded **twice** on the same second → classic **Zerologon / null session** signature.
- `IEUser` logged on to `MSEDGEWIN10` → the attacker's session.
- `01566S-WIN16-IR$` and `02694W-WIN10$` end in **`$`** — these are **machine accounts** (the computer's own identity in AD), logging in with the 4624 event and `LogonType 3` (network). Seeing a *machine* account is normal; seeing it *often* is not.
- `samir` and `Administrator` on domain `3B` → **successful interactive admin logons to a domain**.
- Only **1** failed logon in the whole set → this is not brute force; it is **credential theft**. The attacker logged in with *valid* stolen credentials.

> **Say this:** "A failed-logon spike means someone is guessing. Almost no failed logons but successful logons with odd accounts means someone already has your passwords. Two different incidents, two different responses."

**Follow-up hunt:** which logons came from where? The failed row's target is `MSEDGEWIN10`, and the attacker in Step 10 (`mimikatz`) was on `PC04.example.corp` as `IEUser` — the same account, different host. Cross-reference the two steps.

---

### Step 10 — Threat hunting without rules

Rules only find what someone already wrote a rule for. Hunting is the opposite.

```powershell
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -k mimikatz
```

Real output — a single finding:

```
2019-03-18 01:07:11.661 +05:30 · Process Access · PC04.example.corp · Sysmon · 10 · 4807
SrcProc:  C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe
TgtProc:  C:\Windows\system32\lsass.exe
Access:   0x1010
EvtxFile: .\EVTX-ATTACK-SAMPLES\Credential Access\sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx

Total findings: 1
```

> **Say this:** "`Sysmon 10` alone means nothing — thousands of processes read other processes every day. But *mimikatz.exe touching lsass.exe with access 0x1010* is a confession. That is why we hunt on relationships, not on event IDs."

**Keywords that actually work on this dataset** — measured, so you can predict the answer:

| Keyword | Scope | Findings | Note |
|---|---|---|---|
| `mimikatz` | Credential Access | **1** | The confession above |
| `powershell` | Credential Access | **59** | Too noisy on its own — good for teaching volume |
| `lsass` | Full dataset | **384** | Every LSASS touch, needs narrowing |
| `ntdsutil` | Full dataset | **1** | DCSync tooling — one clean hit |
| `vssadmin` | Full dataset | **7** | Shadow-copy deletion = ransomware precursor |
| `procdump` | Full dataset | **6** | Memory dumping |
| `sekurlsa` | Full dataset | **0** | ⚠️ The mimikatz *file name* contains it, but the field value does not |
| `rar.exe` | Full dataset | **0** | Not present in these samples |

> **⚠️ `sekurlsa` returns 0 findings even though `mimikatz` returns 1.** This is the most confusing moment in the demo and it is a *teaching moment*. The file is named `..._sekurlsa_...` but Hayabusa searches the **parsed event field values**, not the filename. `sekurlsa` is a mimikatz *command*, not a field value in the event — so it is not searchable. Meanwhile `-k mimikatz` matches because the **image path** contains the word.
>
> **Say this:** "Search reads the data, not the filenames. And you can't guess what a tool will find — always run it and see."
>
> **Also note:** keyword search is **case-sensitive** by default. `-k MIMIKATZ` returns **0 findings**; `-k mimikatz` returns 1. Add `-i` for case-insensitive:
> ```powershell
> .\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -k MIMIKATZ -i
> ```

**How to pass more than one keyword** — repeat the `-k` flag (this is the single most common syntax mistake):

```powershell
# OR logic (default): find events containing mimikatz OR ntdsutil OR vssadmin
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES" -k mimikatz -k ntdsutil -k vssadmin

# AND logic: only events containing both terms
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES" -k mimikatz -k lsass -a

# Regex instead of keywords
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES" -r "mimi.*lsass"

# Case-insensitive
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES" -k MIMIKATZ -i
```

> `-k mimikatz,sekurlsa` (comma inside one argument) returns **0 findings** — the comma becomes part of the search string. Always repeat `-k`.

**Narrowing a noisy hunt** — `lsass` gives 384 hits, which is still a haystack. Filter by channel with `-F`:

```powershell
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES" -k lsass -F Sysmon
```

> `-F` filters on a specific field (e.g. `Sysmon`, `Security`, `Microsoft-Windows-Sysmon`). Note `-F` means **field filter** in `search`, but in `dfir-timeline` `-F` means `--no-field-data-mapping` — **the same letter means different things in different subcommands.** Check `-h` before you guess.

---

### Step 11 — Map findings to MITRE ATT&CK

Beginners need this column — it turns "a rule fired" into "the attacker is in phase X of their campaign".

```powershell
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -p verbose -o mitre.csv -w -C
```

`-p verbose` = the output profile. Compare with the default:

```powershell
.\hayabusa.exe list-profiles
```

Available profiles: `minimal`, `standard`, `verbose`, `all-field-info`, `all-field-info-verbose`, `super-verbose`, `timesketch-minimal`, `timesketch-verbose`.

The `verbose` profile adds `MitreTactics` and `MitreTags` to the standard column set:

```
verbose: %Timestamp%, %RuleTitle%, %Level%, %Computer%, %Channel%, %EventID%,
         %MitreTactics%, %MitreTags%, %OtherTags%, %RecordID%, %Details%,
         %ExtraFieldInfo%, %RuleFile%, %RuleID%, %EvtxFile%
```

`super-verbose` adds even more: `%RuleAuthor%`, `%RuleModifiedDate%`, `%Status%`, `%Provider%`, `%RuleCreationDate%`. Useful for auditing *which rule version* fired.

```powershell
Import-Csv .\mitre.csv | Where-Object Level -eq 'crit' |
    Select-Object RuleTitle, MitreTactics, MitreTags | Format-List
```

```
RuleTitle    : HackTool - Mimikatz Kirbi File Creation
MitreTactics : CredAccess
MitreTags    : T1558

RuleTitle    : Hacktool Execution - Imphash
MitreTactics : CredAccess ¦ ResDev
MitreTags    : T1588.002 ¦ T1003

RuleTitle    : HackTool - Dumpert Process Dumper Default File
MitreTactics : CredAccess
MitreTags    : T1003.001

RuleTitle    : HackTool - Dumpert Process Dumper Execution
MitreTactics : CredAccess
MitreTags    : T1003.001

RuleTitle    : Potential Credential Dumping Via LSASS Process Clone
MitreTactics : CredAccess
MitreTags    : T1003 ¦ T1003.001
```

> **Say this:** "T1003 is OS Credential Dumping; T1003.001 is specifically LSASS memory. T1558 is Kerberos ticket theft. `ResDev` means Resource Development — the attacker is *building tooling*. We are not just seeing an alert, we are seeing the attacker's plan."

**Note the `¦` separator** (a broken-bar character) between multiple tags — it is one character, not a pipe or a comma, and PowerShell will not split on it automatically. To count technique usage:

```powershell
Import-Csv .\mitre.csv |
    ForEach-Object { $_.MitreTags -split '¦' } |
    Group-Object | Sort-Object Count -Descending | Select-Object -First 10
```

---

### Step 12 — Scale up: the entire dataset

Now the punchline. Same command, no tuning, all 278 files from every tactic:

```powershell
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -o full-report.csv -H full-report.html -w -C
```

Measured result:

```
Total event log files: 278
Total file size: 46.5 MiB
Total detection rules: 4,674
Events with hits / Total events: 3,132 / 7,033 (Data reduction: 3,901 events (55.47%))

Total | Unique detections: 5,388 | 447
Total | Unique critical detections:  25 (0.46%) | 12 (2.68%)
Total | Unique high detections:     611 (11.34%) | 190 (42.51%)
Total | Unique medium detections:   947 (17.58%) | 150 (33.56%)
Total | Unique low detections:      538 (9.99%) | 51 (11.41%)
Total | Unique informational:     3,267 (60.63%) | 44 (9.84%)

Saved file: full-report.csv (4.6 MiB)
HTML report: full-report.html (439 KB)
Elapsed time: 00:00:13.773
```

> **Say this:** "278 log files, 46.5 MB, 4,674 rules, every ATT&CK tactic — **fourteen seconds** on a laptop. Try that by hand in Event Viewer before lunch."

**The scaling lesson.** Compare the two scans:

| | Credential Access | Full dataset |
|---|---|---|
| Files | 39 | 278 (7.1×) |
| Size | 15.6 MiB | 46.5 MiB (3.0×) |
| Unique detections | 99 | 447 (4.5×) |
| Unique **critical** | 6 | 12 (2.0×) |
| Elapsed | ~12–15 s | ~14 s |

> **Say this:** "We multiplied the log volume by three and the runtime barely moved — because the cost is dominated by **rule loading**, which happens once. More logs means more matches, not slower scanning. This is exactly why you can run detection across a whole enterprise in minutes."

Worth calling out: only **7,033** events were actually *parsed* even though the folder holds far more raw records. Hayabusa's default **channel filter** skips event channels that no loaded rule cares about. That is a deliberate speed/memory trade-off. To force a full read, add `-a` (`--scan-all-evtx-files`) — but expect it to be slower and to find nothing new:

```powershell
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -a -o allscan.csv -w -C
```

```
Total event log files: 39
Events with hits / Total events: 216 / 29,853 (Data reduction: 29,637 events (99.28%))
Total | Unique detections: 392 | 99
```

> **Say this:** "With `-a`, Hayabusa reads **29,853** events instead of 329 — a 90× increase — and finds **exactly the same 99 unique detections**. The channel filter was never hiding anything. It was saving you time."

---

### Step 13 — Wrap-up + exercises

Summary slide material:

1. **Detection engineering beats manual review.** 329 events → 6 critical alerts.
2. **Context converts data into intelligence.** A raw Event ID 10 is useless; mimikatz → lsass.exe is a crime.
3. **Severity enables triage.** You cannot investigate everything; you must rank.
4. **Prioritise by severity, not volume.** `LAPTOP-JU4M3I0E` had the most events and zero critical alerts.
5. **Timelines are the output format of DFIR.** Every tool you will use produces one.
6. **Rules are community knowledge.** 4,674 people's expertise, applied in 14 seconds.

Hand students these exercises. Every command below was run and verified on this machine:

| Exercise | Command to start with | Verified result |
|---|---|---|
| Find a **persistence** mechanism | `.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Persistence" -o persist.csv -w -C` | 22 files |
| Find a **lateral movement** technique | `.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Lateral Movement" -o lateral.csv -w -C` | 47 files · 1,238 detections |
| Which event IDs dominate this dataset? | `.\hayabusa.exe eid-metrics -d ".\EVTX-ATTACK-SAMPLES"` | Event ID table, 1.1 s |
| What other tools ran on the victim? | `.\hayabusa.exe pivot-keywords-list -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -o pivot -w -C` | 12 `pivot-*.txt` files |
| Feed results into a SIEM | `.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -o out.json -t json -w -C` | JSON timeline |
| Tune noise down for a real SOC | `.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -o siem.csv -w -P -C` | 1,161 rules · 5,191 detections |

**Useful extras for advanced students:**

```powershell
# Escalate to privilege escalation and compare detection counts
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Privilege Escalation" -o privesc.csv -w -C
#   -> 66 files, 831 detections, 138 unique

# Only the rules tagged as execution techniques
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" --include-tag attack.execution -o exec.csv -w -C
#   -> 1,449 rules, 463 detections, 112 unique

# Only critical rules (not a severity floor - a rule selection)
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -e critical -o only-critical.csv -w -C
#   -> 217 rules, 25 critical detections, 12 unique
```

> **Note the difference between `-m` and `-e`:** `-m critical` sets a **minimum severity floor** — every rule at `critical` or above loads. `-e critical` (`--exact-level`) loads **only** rules whose level is exactly `critical`. When the highest level is `critical` the two converge: both load 217 rules, and `-m critical` finds 8 critical detections on Credential Access while `-e critical` finds 25 across the full dataset.
>
> The difference becomes visible at lower levels — measured on `Credential Access`:
>
> | Flag | Rules loaded | Detections | Unique |
> |---|---|---|---|
> | `-m high` (high and above) | 2,435 | 84 | 35 |
> | `-e high` (high only) | 2,218 | 76 | 29 |
>
> The 217-rule gap is exactly the `critical` rules that `-m` includes and `-e` excludes.

### Full lab series (20 minutes each)

This guide is **Lab 1**. Two follow-on labs are written as standalone guides inside the tactic folders:

| Lab | Folder guide | Theme | Data |
|---|---|---|---|
| 1 — Credential Access | this file | Stealing passwords: mimikatz, LSASS, DCSync | 39 files · 392 detections |
| 2 — Privilege Escalation | [Privilege Escalation/README.md](<./EVTX-ATTACK-SAMPLES/Privilege Escalation/README.md>) | "UAC is not a security boundary" — UACMe, Potato attacks | 66 files · 831 detections |
| 3 — Lateral Movement | [Lateral Movement/README.md](<./EVTX-ATTACK-SAMPLES/Lateral Movement/README.md>) | "Follow the admin share" — Impacket, CrackMapExec, PsExec | 47 files · 1,238 detections |

Teaching order matters: **steal credentials → escalate on the host → move to the next host** is the real attack chain, and each lab ends where the next one begins.

---

## 6a. Complete command reference

Hayabusa v4.2.0 ships **18 subcommands**. Everything the tool can do is on this list — run `.\hayabusa.exe help` to see it live.

---

### 1. `dfir-timeline` — the main command ⭐

> *"Create a DFIR timeline."*

**What it does:** Reads `.evtx` files, matches every event against every loaded rule, and writes one consolidated, severity-ranked timeline.

```powershell
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -o report.csv -H report.html -w -C
```

**Why it matters:** This is 80% of what you will ever do with Hayabusa. Every other command is a specialised helper around it.

**Key flags:**
| Flag | Meaning |
|---|---|
| `-d` / `-f` | Scan a directory, or one file |
| `-l` | Scan the **live** machine (`C:\Windows\System32\winevt\Logs`) |
| `-o` | Output file |
| `-t` | Format: `csv` (default), `json`, `jsonl` |
| `-H` | Also write an HTML report |
| `-p` | Output profile (`standard`, `verbose`, `super-verbose`…) |
| `-m` | Minimum severity to load rules for |
| `-w` | No wizard — scan everything without asking |
| `-C` | Overwrite existing output |

**Output:** a CSV with one row per detection, plus a console summary of severity counts, top rules, top hosts and date breakdowns.

---

### 2. `search` — hunt without rules ⭐

> *"Search all events by keyword(s) or regular expression."*

**What it does:** Free-text / regex search across raw event field values. **No detection rules involved** — this is raw data hunting.

```powershell
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -k mimikatz
```

**Why it matters:** Rules only find what someone already thought to write a rule for. Hunting is the opposite — you search for something *you* suspect. This is the analyst's most powerful habit.

**Key flags:**
| Flag | Meaning |
|---|---|
| `-k` | Keyword. **Repeat the flag** for OR logic: `-k mimikatz -k lsass` |
| `-a` | AND the keywords instead of OR |
| `-r` | Regex instead of keywords |
| `-i` | Case-insensitive |
| `-F` | Filter by field (e.g. `-F Sysmon`) |
| `-J` / `-L` | Save as JSON / JSONL |

**Gotcha:** search reads **parsed field values**, not filenames — `-k sekurlsa` returns 0 findings even though the *filename* contains "sekurlsa".

---

### 3. `computer-metrics` — which host is noisy? ⭐

> *"Output the total number of events according to computer names."*

**What it does:** Counts events per hostname, and reports OS version, uptime and timezone.

```powershell
.\hayabusa.exe computer-metrics -d ".\EVTX-ATTACK-SAMPLES\Credential Access"
```

**Output:**
```
Total computers: 9
LAPTOP-JU4M3I0E                 29,528 events
IEWIN7                          96 events
MSEDGEWIN10                     70 events
...
```

**Why it matters:** Instant scoping. But **volume ≠ compromise** — `LAPTOP-JU4M3I0E` has the most events and zero critical alerts (see Step 8).

---

### 4. `logon-summary` — who logged in? ⭐

> *"Output a summary of successful and failed logons."*

**What it does:** Parses Security 4624 (success) and 4625 (failure) and summarises by account.

```powershell
.\hayabusa.exe logon-summary -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -o logon-summary -C
```

**Output:** two files — `logon-summary-successful.csv` and `logon-summary-failed.csv`.

**Why it matters:** A failed-logon spike means **guessing** (brute force). Almost no failures but odd successes means someone already **has** the passwords. Two incidents, two responses.

---

### 5. `eid-metrics` — which event IDs dominate?

> *"Output event ID metrics."*

**What it does:** Frequency table of event IDs across the dataset, with percentage, channel and a human description.

```powershell
.\hayabusa.exe eid-metrics -d ".\EVTX-ATTACK-SAMPLES"
```

**Why it matters:** Shows the *shape* of the data — which event types a log set is mostly made of. Useful for deciding which channels to focus a hunt on.

---

### 6. `log-metrics` — log file metadata

> *"Output evtx file metadata."*

**What it does:** Per-file inventory — size, channel, provider, first/last event, record count.

```powershell
.\hayabusa.exe log-metrics -d ".\EVTX-ATTACK-SAMPLES\Credential Access"
```

**Why it matters:** Log triage. Before analysing 278 files, find out what each one actually contains. Also reveals corrupted or empty logs early.

---

### 7. `pivot-keywords-list` — generate hunting pivots

> *"Create a list of pivot keywords."*

**What it does:** Extracts every distinct username, IP, process, command line and logon ID into separate `pivot-*.txt` files.

```powershell
.\hayabusa.exe pivot-keywords-list -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -o pivot -w -C
```

**Output:** 12 files — `pivot-Users.txt`, `pivot-IP Addresses.txt`, `pivot-Processes.txt`, `pivot-Command Lines.txt`, `pivot-Logon IDs.txt`, etc.

**Why it matters:** **This is how you turn one finding into many.** You find `mimikatz.exe` → add it to your pivot list → search every log for it. Pivoting is how a single detection becomes an investigation.

---

### 8. `config-critical-systems` — find DCs and file servers

> *"Find critical systems like domain controllers and file servers."*

**What it does:** Identifies critical infrastructure by the *behaviour* unique to those roles:
- **Security 4768** (Kerberos TGT requested) → **domain controller**
- **Security 5145** (network share access) → **file server**

```powershell
.\hayabusa.exe config-critical-systems -d ".\EVTX-ATTACK-SAMPLES\Credential Access"
```

**Output:**
```
Domain Controllers found (1):
01566s-win16-ir.threebeesco.com
```

**Why it matters:** Hostnames added to `config\critical_systems.txt` get all alerts above `low` **raised one level** (capped at `emergency`). A `medium` alert on a domain controller becomes a `high`. Context changes priority.

> **⚠️ Do NOT pipe this command.** It calls `unwrap()` on a terminal handle and panics if you pipe it:
> ```
> thread 'main' panicked at src\timeline\config_critical_systems.rs:190:26:
> called `Result::unwrap()` on an `Err` value: IO(Custom { kind: NotConnected, error: "not a terminal" })
> ```
> Run it bare, straight to the screen. It also **writes to** `config\critical_systems.txt`.

---

### 9. `extract-base64` — decode obfuscated payloads

> *"Extract and decode base64 strings from events."*

**What it does:** Finds base64-encoded blobs in event data and decodes them.

```powershell
.\hayabusa.exe extract-base64 -d ".\EVTX-ATTACK-SAMPLES\Credential Access"
```

**Why it matters:** Attackers base64-encode PowerShell and C2 payloads to evade keyword matching. This turns the encoded blob back into readable script. It is the single most useful command for turning an opaque detection into an actionable one.

---

### 10. `sort-csv` — merge and order timelines

> *"Sort a Hayabusa CSV by timestamp and remove duplicate detections."*

**What it does:** Sorts one or many Hayabusa CSVs by timestamp and removes duplicate detections.

```powershell
.\hayabusa.exe sort-csv -f report.csv -o sorted.csv -C
.\hayabusa.exe sort-csv -d ".\exports" -o merged.csv -C     # merge many
```

**Why it matters:** You will often collect CSVs from several machines or several tools. `sort-csv` merges them into one chronological timeline with duplicates removed.

> **⚠️ It takes `-f <FILE>` or `-d <DIR>` — not `-i`.** Using `-i` fails with `unexpected argument '-i' found`.

**Verified:** 392 rows in → 392 rows out, but **re-ordered by timestamp** (unsorted file started at `2017-06-10` then `2019-03-25`; sorted file goes `2017-06-10` → `2019-03-18` → `2019-03-18`).

---

### 11. `list-profiles` — what output shapes are available?

> *"List the output profiles for the DFIR timeline."*

**What it does:** Prints all 8 output profiles and the exact fields each one contains.

```powershell
.\hayabusa.exe list-profiles
```

```
minimal, standard, verbose, all-field-info, all-field-info-verbose,
super-verbose, timesketch-minimal, timesketch-verbose
```

**Why it matters:** A profile is a saved column set. `standard` = the 10 columns in the README's Step 5 table. `verbose` adds `MitreTactics` / `MitreTags`. `timesketch-*` is pre-shaped for Timesketch import.

---

### 12. `set-default-profile` — change the default columns

> *"Set default output profile for the DFIR timeline."*

**What it does:** Changes which profile is used when you don't pass `-p`.

```powershell
.\hayabusa.exe set-default-profile -p verbose
```

**Writes to:** `config\default_profile_name.txt`

**Why it matters:** Stops you typing `-p verbose` on every command. **⚠️ It rewrites `config\default_profile.yaml` with different line endings**, which shows up as a spurious diff in git — expect it and don't commit it blindly.

---

### 13. `level-tuning` — adjust severities per rule

> *"Tune alert levels for the DFIR timeline."*

**What it does:** Applies the per-rule severity overrides from `rules\config\level_tuning.txt` to the actual rule files.

```powershell
.\hayabusa.exe level-tuning -f ".\rules\config\level_tuning.txt"
```

**Output** — current → tuned level per rule:
```
path: ./rules\sigma\builtin\process_creation\proc_creation_win_hktl_rubeus.yml
level: critical -> high
path: ./rules\sigma\builtin\security\win_security_ad_replication_machine_account.yml
level: medium -> critical
```

**Why it matters:** Rule authors set a default severity. **Your environment decides the real one.** If DCSync never occurs legitimately in your org, it is not a `medium` — it is a `critical`. This is how you tune a community rule set without forking it.

> **⚠️ This command MODIFIES RULE FILES IN PLACE.** After running it, `git status` shows the changed `.yml` files. Run `git checkout -- rules/` to revert if you were only experimenting.

---

### 14. `update-rules` — pull the latest detections

> *"Update to the latest rules in the hayabusa-rules github repository."*

**What it does:** Pulls the newest rules from [Yamato-Security/hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules).

```powershell
.\hayabusa.exe update-rules
.\hayabusa.exe update-rules -r "C:\MyRules"    # custom location
```

**Why it matters:** The rule set grows every week. A new technique gets a new rule — and your tool becomes more valuable the longer you keep it.

> **⚠️ Requires internet.** Not needed in class, and it will **restore the 35 upstream doc/script files** that were trimmed from this local clone. Run it only when you actually want fresh rules.

---

### 15. `expand-list` — show rule placeholders

> *"Extract expand placeholders from the rules folder."*

**What it does:** Lists the placeholder variables that rules can be expanded with.

```powershell
.\hayabusa.exe expand-list
```

**Output:**
```
10 unique expand placeholders found:
Admins_Workstations, internal_domains, DC-MACHINE-NAME, known_cdcs,
userdomain, Workstations, legit_ips, dc_ip_addresses,
dc_machine_accounts, domain_controller_hostnames
```

**Why it matters:** Some rules are *generic* ("a domain controller did X"). Expand placeholders let you tell Hayabusa **your** domain controllers and workstations, turning a generic rule into one that knows your estate.

---

### 16. `list-contributors` — who built this?

> *"Print the list of contributors."*

**What it does:** Lists the developers and rule authors.

```powershell
.\hayabusa.exe list-contributors
```

**Output includes:**
```
Zach Mathis (@yamatosecurity, Yamato Security Founder): Project leader, tool and concept design, rule creation and tuning
Yusuke Matsui (@apt773): AD hacking working group leader, rule testing, documentation, research
ItiB (@itiB_S144): Core developer (sigmac hayabusa backend, search command)
James Takai / hachiyone: Second lead developer (Tokio multi-threading, sigma aggregation logic)
...
```

**Why it matters:** Credibility and context. **Zach Mathis is the founder and also the most prolific rule author (31 rules)** — the Step 3 author table is not a coincidence.

> The tool also credits **Omer BenAmram** for the Rust `evtx` crate — the parser library underneath the whole engine.

---

### 17. `help` — the built-in manual

> *"Print this message or the help of the given subcommand(s)."*

```powershell
.\hayabusa.exe help
.\hayabusa.exe dfir-timeline -h
.\hayabusa.exe search -h
```

**Why it matters:** Every flag in this guide came from here. **Always check `-h` before assuming a flag's meaning** — `-a` and `-F` mean different things in `search` and `dfir-timeline`.

---

### 18. `config-critical-systems` · `expand-list` · `extract-base64` · `level-tuning` — the tuning layer

Covered above (items 8, 9, 13, 15). These four exist for one reason: **the rules are community knowledge, and a deployment must adapt them to its own environment** without forking the rule set.

---

## 6b. Quick reference table

### The four you will use in class

| Command | Purpose | Used in |
|---|---|---|
| `dfir-timeline` | **The main command.** Scan logs → severity-ranked timeline | Steps 3–7, 11–12 |
| `search` | Raw keyword/regex hunt across all events, no rules needed | Step 10 |
| `computer-metrics` | Which hosts, how many events each | Step 8 |
| `logon-summary` | Successful vs failed logons | Step 9 |

### Timeline and output

| Command | Purpose | Notes |
|---|---|---|
| `dfir-timeline` | Scan a directory/file of `.evtx` and emit a detection timeline | `-o` CSV/JSON/JSONL, `-H` HTML, `-p` profile, `-m` min level |
| `sort-csv` | Sort a Hayabusa CSV by timestamp and de-duplicate | Takes `-f <FILE>` or `-d <DIR>`, **not** `-i` |
| `list-profiles` | Print all output profiles and their fields | 8 profiles |
| `set-default-profile` | Change the profile used when `-p` is omitted | Default is `standard` |

### Investigation and triage

| Command | Purpose | Notes |
|---|---|---|
| `computer-metrics` | Event counts per computer name | Also shows OS/UpTime/Timezone columns |
| `eid-metrics` | Event ID frequency table | Answers "which events dominate?" |
| `log-metrics` | Per-file metadata: size, channel, provider, first/last event | Great for log triage |
| `logon-summary` | Successful/failed logon breakdown | Writes `*-successful.csv` + `*-failed.csv` |
| `pivot-keywords-list` | Extract pivot keywords into `pivot-*.txt` files | 12 files written: users, IPs, processes, command lines, logon IDs |
| `config-critical-systems` | Identify domain controllers and file servers | Finds DCs via Security **4768**, file servers via **5145** · **do not pipe** |
| `extract-base64` | Extract and decode base64 blobs from events | Excellent for decoding obfuscated PowerShell |

### Rule and configuration management

| Command | Purpose | Notes |
|---|---|---|
| `update-rules` | Pull the latest rules from `hayabusa-rules` | **Requires internet** — not needed in class |
| `level-tuning` | Adjust alert levels per rule | **Modifies rule files in place** |
| `expand-list` | List expand placeholders in the rules folder | 19 expand rules in this set |
| `list-contributors` | Print the rule contributors | Same authors as the Step 3 table |
| `help` | Print help for any subcommand | `hayabusa.exe dfir-timeline -h` |

### Complete `dfir-timeline` flag reference

**Input**
| Flag | Meaning |
|---|---|
| `-d, --directory <DIR>` | Directory of `.evtx` files |
| `-f, --file <FILE>` | One `.evtx` file |
| `-l, --live-analysis` | Analyse the live `C:\Windows\System32\winevt\Logs` |

**Filtering**
| Flag | Meaning |
|---|---|
| `-m, --min-level <LEVEL>` | Minimum rule severity to load (default `informational`) |
| `-e, --exact-level <LEVEL>` | Load rules with one exact level: `informational`, `low`, `medium`, `high`, `critical` |
| `-P, --proven-rules` | Only the 1,277 vetted, low-false-positive rules |
| `-a, --scan-all-evtx-files` | Read **all** channels (disable the event channel filter) |
| `-A, --enable-all-rules` | Load **all** rules (disable the rule filter) |
| `--include-tag <TAG...>` | Only rules with these tags (e.g. `attack.execution`) |
| `--exclude-tag <TAG...>` | Skip rules with these tags |
| `--include-category <CATEGORY...>` | Only rules for these logsource categories (e.g. `process_creation`) |
| `--exclude-category <CATEGORY...>` | Skip rules for these logsource categories |
| `--include-status <STATUS...>` | Only rules with these statuses (e.g. `stable`, `test`) |
| `--exclude-status <STATUS...>` | Skip rules with these statuses |
| `--include-computer <COMPUTER...>` | Scan only these hostnames |
| `--exclude-computer <COMPUTER...>` | Skip these hostnames |
| `--include-eid <EID...>` | Scan only these event IDs (e.g. `1,4688`) — faster |
| `--exclude-eid <EID...>` | Skip these event IDs — faster |
| `-x, --recover-records` | Carve records from EVTX slack space |

> **⚠️ There is no `--include-channel` flag.** The closest are `--include-category` (logsource category, e.g. `process_creation`) and the channel filter itself, which is controlled by `-a` / `-A`. Using `--include-channel` fails with `unexpected argument '--include-channel' found`.

> **💡 `--include-eid` / `--exclude-eid` are the best speed knobs.** Scanning only the event IDs you care about skips the rest entirely — far more effective than `-m` for a targeted hunt.

**Output**
| Flag | Meaning |
|---|---|
| `-o, --output <FILE>` | Output file |
| `-t, --output-type <FMT>` | `csv` (default), `json`, `jsonl` |
| `-p, --profile <PROFILE>` | Output profile (see `list-profiles`) |
| `-H, --html-output` | Also write an HTML report |
| `-T, --visualize-timeline` | Terminal frequency visualisation (needs unicode) |
| `-M, --multiline` | Newline-separate event fields (CSV only) |
| `-F, --no-field-data-mapping` | Disable field data mapping |

**General**
| Flag | Meaning |
|---|---|
| `-w, --no-wizard` | Don't ask questions — scan everything |
| `-C, --clobber` | Overwrite existing output files |
| `-s, --sort` | Sort results before saving (uses more memory) |
| `--threads <N>` | Thread count (default: optimal) |
| `--timeline-start` / `--timeline-end` | Time-window the scan |
| `-V, --validate-checksums` | Validate record checksums |
| `-q, --quiet` | Suppress the banner |
| `-K, --no-color` | Disable ANSI colour |
| `-Q, --quiet-errors` | Don't write error logs |

### Complete `search` flag reference

| Flag | Meaning |
|---|---|
| `-k, --keyword <KEYWORD...>` | Search by keyword. **Repeat the flag** for OR logic |
| `-a, --and-logic` | AND the keywords instead of OR |
| `-r, --regex <REGEX>` | Search by regular expression |
| `-i, --ignore-case` | Case-insensitive keyword search |
| `-F, --filter <FILTER...>` | Filter by specific field(s) |
| `-J, --json-output` | Save as JSON |
| `-L, --jsonl-output` | Save as JSONL |
| `-M, --multiline` | Newline-separate fields in CSV output |
| `-S, --tab-separator` | Tab-separate fields |
| `--time-offset <OFFSET>` | Only recent events (`1y`, `3M`, `30d`, `24h`, `30m`) |

> **⚠️ Remember the collision:** in `search`, `-a` = AND-logic and `-F` = field filter. In `dfir-timeline`, `-a` = scan-all-files and `-F` = no-field-data-mapping. **Always run `hayabusa.exe <subcommand> -h` before assuming.**

### Practical recipes

```powershell
# --- Triage: only what matters ---------------------------------------------
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -m critical -o crit.csv -w -C

# --- Production: proven rules only, less noise -----------------------------
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -P -o siem.csv -w -C

# --- SIEM handoff: JSONL (one object per line, ideal for Elastic) ----------
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -o out.jsonl -t jsonl -w -C

# --- Merge many CSV exports into one sorted timeline -----------------------
.\hayabusa.exe sort-csv -d ".\exports" -o merged.csv -C

# --- Identify domain controllers in a customer estate ----------------------
.\hayabusa.exe config-critical-systems -d "C:\Collected\Logs"

# --- Decode obfuscated PowerShell payloads ---------------------------------
.\hayabusa.exe extract-base64 -d ".\EVTX-ATTACK-SAMPLES\Credential Access"

# --- Profile every event by host and event ID -------------------------------
.\hayabusa.exe log-metrics   -d ".\EVTX-ATTACK-SAMPLES" | Out-File .\log-metrics.txt
.\hayabusa.exe eid-metrics   -d ".\EVTX-ATTACK-SAMPLES" | Out-File .\eid-metrics.txt

# --- Time-windowed scan (incident timeframe) --------------------------------
.\hayabusa.exe dfir-timeline -d ".\Logs" --timeline-start "2020-09-11 00:00:00 +05:30" -w -C

# --- Narrow to one event ID (LSASS access = Sysmon 10) ----------------------
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Credential Access" --include-eid 10 -o eid10.csv -w -C
#   -> 34 hits, 75 detections, 11 unique  (vs 392/99 for the full scan)

# --- Narrow to one logsource category ---------------------------------------
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Credential Access" --include-category process_creation -o cat.csv -w -C
#   -> 2,759 rules, 48 detections, 26 unique

# --- Live analysis of the machine you are sitting on ------------------------
.\hayabusa.exe dfir-timeline -l -o live.csv -w -C
```

> **⚠️ `config-critical-systems` crashes if you pipe it.** It calls `unwrap()` on a terminal handle, so `| Select-Object` or `| Out-File` produces:
> ```
> thread 'main' panicked at src\timeline\config_critical_systems.rs:190:26:
> called `Result::unwrap()` on an `Err` value: IO(Custom { kind: NotConnected, error: "not a terminal" })
> ```
> Run it **bare**, straight to the screen, with no pipe. It also *writes to* `config\critical_systems.txt`.

---

## 7. Command cheat sheet

Copy-paste ready. All assume you are in the demo folder.

> **`-C` is on every writing command on purpose.** Hayabusa refuses to overwrite an existing file and errors out *before* scanning. Drop `-C` and the demo dies on the second run.

```powershell
# --- Core scan -------------------------------------------------------------
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -o report.csv -H report.html -w -C

# --- One single file -------------------------------------------------------
.\hayabusa.exe dfir-timeline -f ".\EVTX-ATTACK-SAMPLES\Credential Access\sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx" -o one.csv -w -C

# --- Severity filters ------------------------------------------------------
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -m critical -o crit.csv -w -C
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -m high     -o high.csv -w -C

# --- Rule selection --------------------------------------------------------
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -P -o proven.csv -w -C          # proven rules only (1,161 rules)
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -e critical -o only-critical.csv -w -C   # only critical rules (217 rules)
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" --include-tag attack.execution -o exec.csv -w -C

# --- Coverage --------------------------------------------------------------
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -a -o allscan.csv -w -C   # read ALL channels (no filter)
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -A -o allrules.csv -w -C   # enable ALL rules (no rule filter)

# --- Output formats --------------------------------------------------------
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -o out.json -t json -w
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -o out.jsonl -t jsonl -w
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -p verbose -o mitre.csv -w -C
.\hayabusa.exe dfir-timeline -d ".\EVTX-ATTACK-SAMPLES" -H report.html -w -C

# --- Investigation helpers -------------------------------------------------
.\hayabusa.exe computer-metrics -d ".\EVTX-ATTACK-SAMPLES\Credential Access"
.\hayabusa.exe logon-summary    -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -o logon-summary -C
.\hayabusa.exe eid-metrics      -d ".\EVTX-ATTACK-SAMPLES\Credential Access"
.\hayabusa.exe log-metrics      -d ".\EVTX-ATTACK-SAMPLES\Credential Access"
.\hayabusa.exe pivot-keywords-list -d ".\EVTX-ATTACK-SAMPLES\Credential Access" -o pivot -w -C

# --- Threat hunting --------------------------------------------------------
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES" -k mimikatz
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES" -k mimikatz -k ntdsutil -k vssadmin   # OR (repeat -k)
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES" -k mimikatz -k lsass -a               # AND
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES" -r "mimi.*lsass"                      # regex
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES" -k MIMIKATZ -i                        # case-insensitive
.\hayabusa.exe search -d ".\EVTX-ATTACK-SAMPLES" -k lsass -F Sysmon                    # filter by field

# --- Housekeeping ----------------------------------------------------------
.\hayabusa.exe help
.\hayabusa.exe dfir-timeline -h
.\hayabusa.exe search -h
.\hayabusa.exe list-profiles
.\hayabusa.exe update-rules          # needs internet
Remove-Item *.csv, *.html, *.json, pivot-*.txt -Force   # clean outputs before class
```

Useful flags, memorised in one line: **`-w`** no wizard · **`-C`** overwrite · **`-m`** min level · **`-p`** profile · **`-t`** format · **`-o`** output · **`-d`** directory · **`-f`** single file.

> **⚠️ The same letter means different things in different subcommands.** Always check `-h`:
> - `-a` = `--and-logic` in **`search`**, but `--scan-all-evtx-files` in **`dfir-timeline`**
> - `-F` = `--filter` (by field) in **`search`**, but `--no-field-data-mapping` in **`dfir-timeline`**
> - `-e` / `-m` / `-p` / `-t` / `-w` / `-C` behave consistently across the main scan commands

---

## 8. Gotchas that will bite you live

| Symptom | Cause | Fix |
|---|---|---|
| `unrecognized subcommand 'csv-timeline'` | Hayabusa **v4 renamed it** | use `dfir-timeline` |
| `[ERROR] The file report.html already exists` | output file from a previous run | add `-C` / `--clobber` |
| `[ERROR] The files with a base name of logon-summary already exist` | same, for `logon-summary` | add `-C` |
| `[ERROR] No .evtx files were found` | trailing backslash before the closing quote (`"dir\"`) — PowerShell escapes the quote | write `"....\Credential Access"` with **no** trailing `\` |
| `Saved file` but the CSV is 0 KB | no detection at that severity level for that input | expected; try a lower `-m` |
| `0 / 0` events scanned | the file's channel is not covered by any loaded rule | add `-a` to force reading all events |
| Rules never load / `rules` not found | exe launched from another directory | `cd` into the demo folder first, or pass `-r .\rules` |
| Very slow first run | cold cache + Defender scanning newly copied files | run the scan once before class to warm the cache (195 s → ~13 s) |
| `.etl` sample produces nothing | only `.evtx` is supported | mention it; skip it |
| `search` returns 0 findings for multiple keywords | `-k a,b` puts the comma in the search string | repeat the flag: `-k a -k b` |
| `search` finds nothing for a keyword you can see in the CSV | keyword search is **case-sensitive** by default | add `-i`, or match the real casing (`PSEXESVC`, `ADMIN$`) |
| `search -k sekurlsa` returns 0 even though the filename contains it | search reads **parsed field values**, not filenames | search the value that is really in the event (e.g. `-k mimikatz`) |
| `-F` behaves unexpectedly | `-F` = field filter in `search`, but `--no-field-data-mapping` in `dfir-timeline` | run `hayabusa.exe <subcommand> -h` to confirm |
| `-a` behaves unexpectedly | `-a` = AND-logic in `search`, but `--scan-all-evtx-files` in `dfir-timeline` | same — check `-h` |
| Chinese/Japanese text in output | Hayabusa prints a Japanese proverb on exit | cosmetic, ignore |
| `config-critical-systems` panics with `not a terminal` | it calls `unwrap()` on a terminal handle and **cannot be piped** | run it bare, straight to the screen — never `\| Select-Object` |
| `level-tuning` changed my rule files | it **modifies rules in place** to apply `level_tuning.txt` | `git checkout -- rules/` to revert after experimenting |
| `set-default-profile` shows up as a git diff | it rewrites `config\default_profile.yaml` with different line endings | `git checkout -- config/default_profile.yaml` if unwanted |
| `sort-csv -i <file>` → `unexpected argument '-i' found` | it takes `-f <FILE>` or `-d <DIR>` | use `-f` |

Three accuracy notes worth knowing before someone asks:

- The `Credential Access` folder holds **40 files**, but only **39** are `.evtx` — `etw_ad_netlogon_provider_zerologon_mimikatz.etl` is an ETL trace, not an event log, so it is skipped.
- `Total events` (329) counts only events from channels that loaded rules care about, **not** every byte in the folder. With `-a` the same folder yields **29,853** events and **exactly the same 99 unique detections**.
- `rules\` contains **5,096 files**, of which **5,000** are `.yml` rules. The scan reports **4,674 detection rules** because deprecated, noisy, unsupported and excluded rules are filtered out before matching.

---

## 9. Reference: expected results

Use this to confirm the tool is behaving correctly.

All values below were **measured on this machine** (warm cache) with Hayabusa v4.2.0. Use this to confirm the tool is behaving correctly.

| Command | Expected |
|---|---|
| `dfir-timeline -d "...\Credential Access"` | 39 files, 15.6 MiB, **392 detections / 99 unique**, ~12–15 s |
| ↳ severity split | crit 8 · high 76 · med 95 · low 85 · info 128 |
| ↳ events scanned | 216 hits / 329 events (34.35% reduction) |
| ↳ channel filter | 37 of 39 files loaded, 4,508 of 4,674 rules enabled |
| `-m critical` on same folder | 217 rules, 8 detections, 97.57% reduction, ~3 s |
| `-a` on same folder | 29,853 events scanned, **same 99 unique detections** |
| `dfir-timeline -d "...\EVTX-ATTACK-SAMPLES"` (all) | 278 files, 46.5 MiB, **5,388 detections / 447 unique**, ~14 s |
| ↳ severity split | crit 25 · high 611 · med 947 · low 538 · info 3,267 |
| `-P` (proven rules) on full dataset | 1,161 rules, 5,191 detections, 411 unique, ~6 s |
| `--include-tag attack.execution` | 1,449 rules, 463 detections, 112 unique, ~6 s |
| `computer-metrics` on Credential Access | 9 computers; `LAPTOP-JU4M3I0E` 29,528 events (noise), `IEWIN7` 96 (real) |
| `logon-summary` on Credential Access | 145 records, 9 successful rows, 1 failed row |
| `search -k mimikatz` | 1 finding (Sysmon 10 on `PC04.example.corp`) |
| `search -k MIMIKATZ` | **0 findings** — case-sensitive; add `-i` for 1 finding |
| `search -k sekurlsa` | **0 findings** — filename, not a field value |
| `search -k lsass` (full dataset) | 384 findings |
| `search -k ntdsutil` / `-k vssadmin` / `-k procdump` | 1 / 7 / 6 findings |
| `dfir-timeline -f <single evtx>` | 1 file, 3 detections, 3 unique |
| `search`/`dfir-timeline` with `-p verbose` | adds `MitreTactics`, `MitreTags` columns |
| `sort-csv -f <csv>` | 392 rows in, 392 rows out, **re-sorted by timestamp** |
| `-A` on Credential Access | same 4,674 rules, same 99 unique detections |
| `config-critical-systems` | finds 1 DC (`01566s-win16-ir.threebeesco.com`) — **do not pipe it** |

Top critical detections you should see in the Credential Access demo:

| RuleTitle | Technique | Computer |
|---|---|---|
| HackTool - Mimikatz Kirbi File Creation | T1558 | MSEDGEWIN10 |
| Hacktool Execution - Imphash | T1588.002 / T1003 | MSEDGEWIN10 |
| HackTool - Dumpert Process Dumper Default File | T1003.001 | alice.insecurebank.local |
| HackTool - Dumpert Process Dumper Execution | T1003.001 | alice.insecurebank.local |
| Potential Credential Dumping Via LSASS Process Clone | T1003 / T1003.001 | DESKTOP-PIU87N6 |
| Potential Credential Dumping Via LSASS Process Clone | T1003 / T1003.001 | MSEDGEWIN10 |

---

## 10. Cleanup after class

```powershell
Remove-Item report.csv, report.html, crit-only.csv, mitre.csv, full-report.csv, full-report.html -Force -ErrorAction SilentlyContinue
Remove-Item one.csv, out.json, out.jsonl, proven.csv, siem.csv, persist.csv, lateral.csv, privesc.csv, high.csv, only-critical.csv, exec.csv, allscan.csv, allrules.csv, cm.txt -Force -ErrorAction SilentlyContinue
Remove-Item logon-summary-*.csv, pivot-*.txt -Force -ErrorAction SilentlyContinue
Remove-Item .\logs -Recurse -Force -ErrorAction SilentlyContinue
```

Leaves the folder with exactly: `hayabusa.exe`, `rules\`, `config\`, `EVTX-ATTACK-SAMPLES\`, `README.md`.

---

## 11. Credits & licences

### Upstream projects

| Project | Author / org | Licence | Role |
|---|---|---|---|
| **[Hayabusa](https://github.com/Yamato-Security/hayabusa)** | **Yamato Security** | **AGPL v3** | The engine (Rust) — v4.2.0, 13 Oct 2026 |
| **[Sigma](https://github.com/SigmaHQ/sigma)** | SigmaHQ / the Sigma community | **DRL 1.1** | The rule format and 4,804 rules |
| **[hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules)** | Yamato Security | AGPL v3 | Tuning, exclusions, proven-rule list |
| **[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)** | **Samir Bousseaden** ([@sbousseaden](https://github.com/sbousseaden)) | GPL | 278 real attack `.evtx` files |
| **[MITRE ATT&CK](https://attack.mitre.org)** | MITRE | — | The tactic/technique taxonomy mapped in the `verbose` profile |

### Key people in this demo

| Name | Contribution |
|---|---|
| **Yamato Security** | Built and maintains Hayabusa |
| **Samir Bousseaden** | Author of the EVTX-ATTACK-SAMPLES dataset; also a Hayabusa rule contributor |
| **Zach Mathis** | Most prolific rule author here (31 rules) |
| **Florian Roth** (Nextron Systems) | 25 rules; author of the 2017 mimikatz keyword rule |
| **Nasreddine Bencherchali** | 14 rules |
| **oscd.community** | 12 rules |

### Licences — read this before corporate use

| Component | Licence | Corporate implication |
|---|---|---|
| Hayabusa engine | **AGPL v3** | Strong copyleft with a **network use clause**. Running it as an analyst tool is fine; embedding it in a commercial product or offering it as a hosted service may require you to publish your source. **Consult legal.** |
| Sigma rules | DRL 1.1 | Sigma's own Detection Rule Licence — permissive for defensive use. |
| EVTX-ATTACK-SAMPLES | GPL | The logs themselves. Fine for training; attribution required on redistribution. |

> **Teaching integrity note:** these are real attack logs captured in lab environments. Explain to students that any *real* customer logs must never leave an organisation, and that the samples here are published for training precisely so they can be shared.

### Learn more

- **Official docs (15 languages):** [yamato-security.github.io/hayabusa](https://yamato-security.github.io/hayabusa/)
- **Command reference:** [yamato-security.github.io/hayabusa/commands](https://yamato-security.github.io/hayabusa/commands/)
- **Rules and Sigma compatibility:** [yamato-security.github.io/hayabusa/rules](https://yamato-security.github.io/hayabusa/rules/)
- **Releases:** [github.com/Yamato-Security/hayabusa/releases](https://github.com/Yamato-Security/hayabusa/releases)
- **Rule issues:** [hayabusa-rules/issues](https://github.com/Yamato-Security/hayabusa-rules/issues) · **Sigma false positives:** [SigmaHQ/sigma/issues](https://github.com/SigmaHQ/sigma/issues)
