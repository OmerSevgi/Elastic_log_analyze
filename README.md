# Sysmon Log Analysis in Elastic: Malicious "Preventivo" Installer

Threat hunting exercise on Sysmon logs ingested into Elastic (Kibana Discover / KQL). The goal was to reconstruct how a victim host was infected by a fake invoice executable downloaded from Dropbox, and to document the attacker's behavior, IOCs and detection ideas.

> **Data source:** _[add the name/link of the lab or dataset here]_. The raw data is not included in this repository.

## Summary

On host `DESKTOP-887GK2L`, user `CyberJunkie` downloaded `Preventivo24.02.14.exe.exe` from Dropbox using Firefox and ran it from Explorer. The file is an installer (internal description "Photo and vn Installer", original file name `Fattura 2 2024.exe`) that:

1. Checked internet connectivity (`www.example.com` / `93.184.216.34`).
2. Launched `msiexec.exe` to install `main1.msi`.
3. Dropped files into `%APPDATA%\Photo and Fax Vn\...\WindowsVolume\Games\` (scripts `.cmd`, `taskhost.exe`, `viewer.exe`, DLLs).
4. Timestomped the dropped files (set creation times back to January 2024).
5. Copied `once.cmd` to `C:\Games\` via `msiexec.exe`.
6. Deleted its staging files and terminated itself within about 2 seconds of the first process start.

## Timeline (UTC, as shown in Elastic)

| Time | Event code | What happened |
|---|---|---|
| 03:41:25.269 | 22 | Firefox resolves `uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com` |
| 03:41:26.459 | 11 | `Preventivo24.02.14.exe.exe` written to `Downloads` by Firefox |
| 03:41:30.472 | 11 / 15 | `Zone.Identifier` created (Mark of the Web; `ReferrerUrl=https://www.dropbox.com/`) |
| 03:41:43.924 | 22 | Firefox resolves `d.dropbox.com` |
| 03:41:56.538 | 1 | `Preventivo24.02.14.exe.exe` executed (parent: `Explorer.EXE`) |
| 03:41:56.955 | 22 | DNS query for `www.example.com` (connectivity check) |
| 03:41:57.159 | 3 | Network connection to `93.184.216.34` |
| 03:41:57.604 | 1 | `msiexec.exe /V` started by `services.exe` (Windows Installer service) |
| 03:41:57.787 | 1 | `MsiExec.exe -Embedding ...` (SysWOW64) |
| 03:41:57.905 | 1 | `msiexec.exe /i ...\main1.msi` with the dropper path in `AI_SETUPEXEPATH` |
| 03:41:58.178 | 1 | Second `MsiExec.exe -Embedding ...` |
| 03:41:58.389 to 03:41:58.420 | 11 | Dropper writes `c.cmd`, `taskhost.exe`, `once.cmd`, `on.cmd`, `cmmc.cmd`, `viewer.exe` |
| 03:41:58.389 to 03:41:58.404 | 2 | Timestomping of dropped files (16 events in total, including `~.pdf`) |
| 03:41:58.577 | 11 | `msiexec.exe` creates `C:\Games\once.cmd` |
| 03:41:58.733 to 03:41:58.748 | 23 | Dropped files and `main1.msi` deleted |
| 03:41:58.795 | 5 | `Preventivo24.02.14.exe.exe` terminates |

Note: Elastic displays the events in 2026, while the raw Sysmon `UtcTime` values show 2024-02-14. The ingestion shifted the year, so I kept the Elastic values for consistency with my queries.

## Findings

| Question | Answer | Query used |
|---|---|---|
| File creation events | 56 (50 unique paths) | `event.code: "11"` |
| Malicious process | `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe` | `event.code: "1"` |
| Distribution channel | Dropbox (`dl.dropboxusercontent.com`, `d.dropbox.com`) | `event.code: "22"`, `event.code: "15"` |
| Timestomp value for the PDF | `2024-01-14 08:10:06.029` (`CreationUtcTime`; previous value `2024-02-14 03:41:58.404`) | `event.code: "2" and *pdf*` |
| Where `once.cmd` was created | `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd`, later also `C:\Games\once.cmd` | `event.code: "11" and file.path: *once.cmd` |
| Connectivity-check domain | `www.example.com` | `event.code: "22" and *Preventivo24*` |
| Contacted IP | `93.184.216.34` | `event.code: "3" and *Preventivo24*` |
| Process termination | `03:41:58.795` | `event.code: "5" and *Preventivo24*` |

## Indicators of Compromise

**File (from Sysmon event 1)**

| Field | Value |
|---|---|
| Path | `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe` |
| MD5 | `32F35B78A3DC5949CE3C99F2981DEF6B` |
| SHA1 | `18A24AA0AC052D31FC5B56F5C0187041174FFC61` |
| SHA256 | `0CB44C4F8273750FA40497FCA81E850F73927E70B13C8F80CDCFEE9D1478E6F3` |
| IMPHASH | `36ACA8EDDDB161C588FCF5AFDC1AD9FA` |
| Original file name | `Fattura 2 2024.exe` |
| Company / description | `Photo and Fax Vn` / `Photo and vn Installer` |

**Network**

- `uc2f030016253ec53f4953980a4e.dl.dropboxusercontent.com`
- `d.dropbox.com`
- `www.example.com` (benign domain used for connectivity check)
- `93.184.216.34`

**Dropped files** (under `%APPDATA%\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\`)

- `main1.msi`, `WindowsVolume\Games\powercfg.msi`
- `WindowsVolume\Games\c.cmd`, `once.cmd`, `on.cmd`, `cmmc.cmd`, `cmd.txt`
- `WindowsVolume\Games\taskhost.exe`, `viewer.exe`, `vnchooks.dll`, `ddengine.dll`, `UltraVNC.ini`
- `WindowsVolume\Games\UVncVirtualDisplay\UVncVirtualDisplay.dll`, `.inf`, `.cat`
- `C:\Games\once.cmd`

The `viewer.exe`, `vnchooks.dll`, `UVncVirtualDisplay` and `UltraVNC.ini` names suggest UltraVNC components, which would point to a remote access tool. This is based on file names only; I did not analyze the binaries.

## MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Execution | T1204.002 User Execution: Malicious File | User launched the downloaded file from Explorer |
| Defense Evasion | T1036.007 Masquerading: Double File Extension | `Preventivo24.02.14.exe.exe` posing as an invoice |
| Defense Evasion | T1218.007 System Binary Proxy Execution: Msiexec | `msiexec.exe /i main1.msi` |
| Defense Evasion | T1070.006 Indicator Removal: Timestomp | 16 Sysmon event 2 records |
| Defense Evasion | T1070.004 Indicator Removal: File Deletion | Sysmon event 23 on dropped files |
| Discovery | T1016.001 Internet Connection Discovery | DNS and connection to `example.com` |
| Command and Control | T1219 Remote Access Software (possible) | UltraVNC-like file names, not confirmed |

## Detection ideas

- Process creation where the image path is in `Downloads` and the file name has a double extension (`*.exe.exe`, `*.pdf.exe`).
- `msiexec.exe /i` with a user-profile MSI path and `AI_SETUPEXEPATH` pointing to a file in `Downloads`.
- Burst of Sysmon event 2 (file creation time changed) from a single process.
- A user-writable process (`Downloads`) followed by `msiexec.exe` writing to a root-level folder such as `C:\Games\`.

## Useful KQL

```
event.code : "1" and process.executable : *Preventivo24*
event.code : "11" and process.executable : *Preventivo24*
event.code : "2"
event.code : "22" and process.executable : *Preventivo24*
event.code : "3" and process.executable : *Preventivo24*
event.code : "23"
event.code : "5" and process.executable : *Preventivo24*
```

## Notes and limitations

- The `event.action` field shows "Dns query (rule: DnsQuery)" for every event in this dataset, so I labeled events by `event.code` instead.
- ATT&CK tags that came with the dataset were noisy (many generic "Services" tags), so the mapping above is my own, based on the observed behavior.
- Hashes come from the Sysmon logs; I did not submit them to external reputation services.
- Analysis is based on a single host and about two minutes of logs.
