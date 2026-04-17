# Invoke-ADSecurityAudit

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue?logo=powershell)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![RSAT Only](https://img.shields.io/badge/requires-RSAT%20only-brightgreen)
![Read Only](https://img.shields.io/badge/AD%20access-read--only-important)

> **Fast, safe, read-only Active Directory security assessment — no infrastructure required.**

Single-file PowerShell script. Run it on a domain-joined machine and get a structured HTML report with findings, MITRE ATT&CK mappings, and remediation guidance. No agents, no databases, no persistent components.

---

## Preview (html report)

<img width="1653" height="809" alt="image" src="https://github.com/user-attachments/assets/ed1ad918-2117-4a48-9dd0-8727f22f5400" />

---

## How it compares

| | This tool | BloodHound | PingCastle |
|---|---|---|---|
| Setup required | ❌ RSAT only | ✅ Neo4j + agent | ✅ Install |
| Read-only | ✅ | ❌ | ✅ |
| Offline report | ✅ Single HTML | ❌ | ✅ |
| MITRE ATT&CK mapping | ✅ | ✅ | ❌ |
| GPO settings analysis | ✅ | ❌ | ❌ |
| Lite mode for large domains | ✅ | ❌ | ❌ |

> These tools serve different purposes. BloodHound excels at attack path enumeration and graph-based analysis. This script is optimised for fast, point-in-time misconfiguration checks — no setup, runs in minutes, useful during IR or routine audits.

---

## What this tool does and does not do

**Does:**
- Checks for misconfigurations that are **frequently exploited or create high-impact attack conditions**
- Maps every finding to MITRE ATT&CK where applicable
- Reads GPO security settings directly from SYSVOL — no GPMC required
- Produces a self-contained HTML report + structured CSV

**Does not:**
- Enumerate attack paths or graph-based lateral movement chains (use BloodHound for that)
- Audit Active Directory Certificate Services (ADCS / ESC1–ESC8)
- Detect Shadow Credentials or Certificate-based attacks
- Analyse hybrid / Azure AD environments
- Replace a full penetration test or red team engagement

---

## Philosophy

Focused on three things:
- **Exploitable over theoretical** — checks target misconfigurations with documented real-world abuse, not edge cases
- **Signal over noise** — each finding includes severity, evidence, and a concrete remediation step
- **No infrastructure** — runs from any domain-joined machine, leaves no persistent components

Severity is based on simple, documented thresholds (password age, group membership, flag presence). The risk score (`CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1`) is a triage aid, not a compliance metric.

---

## Design principles

- **Read-only** — only LDAP reads, SYSVOL file reads, and `Get-ACL` calls. No `Set-AD*`, `New-AD*`, `Remove-AD*`, no RPC execution, no WMI, no PowerShell Remoting
- **Graceful degradation** — missing permissions or modules produce console warnings, not crashes
- **Consistent output** — same environment always produces the same findings; no randomness or sampling
- **Full data** — complete object lists in CSV; HTML truncates to 100 objects per finding for performance

---

## How it works

- **LDAP queries** via the RSAT `ActiveDirectory` module — server-side filtered where possible, avoids unnecessary full-domain enumeration
- **SYSVOL reads** over SMB for GPP password scanning (Check 19) and GPO security settings (Check 22)
- **ACL inspection** via `Get-ACL` on specific AD object paths — domain root, AdminSDHolder, DC OU, and up to 10 privileged user objects
- **No RPC execution, no WMI, no PowerShell Remoting** — all data collection is passive read-only

---



## Use cases

- **Incident response triage** — quickly surface the highest-risk misconfigurations before going deeper
- **Pre-pentest baseline** — document the state of the domain before a red team engagement
- **Internal AD audit** — structured output suitable for reporting and ticketing
- **Continuous hygiene** — schedule Lite mode weekly, Full mode monthly
- **Hardening validation** — re-run after remediation to confirm findings are resolved

---

## Quick start

```powershell
# Clone
git clone https://github.com/zavetsec/Invoke-ADSecurityAudit
cd Invoke-ADSecurityAudit

# Or download the script directly and run from its directory
# https://github.com/zavetsec/Invoke-ADSecurityAudit/raw/main/Invoke-ADSecurityAudit.ps1

# Full audit — auto-detect PDC, save report to script directory
.\Invoke-ADSecurityAudit.ps1

# Lite mode — 9 high-impact checks, ~2–5 min
.\Invoke-ADSecurityAudit.ps1 -LiteMode

# Non-domain machine or explicit credentials
.\Invoke-ADSecurityAudit.ps1 -Server dc01.corp.local -Credential (Get-Credential)
```

Reports are saved to the script directory as `ADSecurityAudit_<timestamp>.html` and `.csv`.

---

## Example finding

```
[HIGH] Kerberoastable account — password age 847 days

  Account      : svc_sql
  SPN          : MSSQLSvc/sql01.corp.local
  Password age : 847 days
  AdminCount   : 0
  TTP          : T1558.003

  Any domain user can request a Kerberos service ticket for this account.
  The ticket is encrypted with the account password and can be cracked offline.

  Recommendation: rotate password to 25+ chars; enforce AES-256 encryption on SPN;
                  consider migrating to gMSA for automatic password management.
```

---

## Installation

No installation. Clone and run.

**Requires RSAT ActiveDirectory module:**

```powershell
# Windows Server
Add-WindowsFeature RSAT-AD-PowerShell

# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools
```

**Optional — for Check 15 (GPO enumeration via GPMC):**

```powershell
# Windows Server
Add-WindowsFeature GPMC

# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
```

Check 15 is the only check requiring GPMC. If absent it is silently skipped. Check 22 covers critical GPO security settings without any additional modules.

---

## Checks

### Full mode — 22 checks

| # | Check | Severity range | MITRE TTP | Notes |
|---|-------|---------------|-----------|-------|
| 1 | Domain / Forest Functional Level | HIGH | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | |
| 2 | Privileged group membership (DA, EA, SA, BA + 6 more) | CRITICAL–MEDIUM | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | |
| 3 | KRBTGT password age | CRITICAL–MEDIUM | [T1558.001](https://attack.mitre.org/techniques/T1558/001/) | |
| 4 | Default Domain Password Policy + Fine-Grained Policies | CRITICAL–MEDIUM | — | |
| 5 | Kerberoastable accounts (SPN + password age + AdminCount) | CRITICAL–MEDIUM | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | |
| 6 | AS-REP Roastable accounts | CRITICAL–HIGH | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | |
| 7 | Unconstrained + constrained delegation with protocol transition | CRITICAL–HIGH | [T1558](https://attack.mitre.org/techniques/T1558/) | |
| 8 | AdminSDHolder orphans (AdminCount=1 outside priv groups) | HIGH | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | |
| 9 | DCSync rights — replication ACEs on domain root | CRITICAL | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | Needs DA |
| 10 | Stale and never-logged-on user accounts | HIGH–LOW | [T1078](https://attack.mitre.org/techniques/T1078/) | |
| 11 | Password flags (NeverExpires, reversible encryption, DES-only) | CRITICAL–HIGH | [T1078](https://attack.mitre.org/techniques/T1078/) | |
| 12 | LAPS deployment coverage | HIGH–MEDIUM | — | `-CheckLAPS` |
| 13 | Stale computer accounts + end-of-life operating systems | CRITICAL–LOW | — | |
| 14 | Domain trust issues (SID filtering, selective auth) | CRITICAL–MEDIUM | — | |
| 15 | GPO enumeration (disabled, unlinked GPOs) | LOW | — | Needs GPMC |
| 16 | Protected Users group coverage | HIGH | — | |
| 17 | Sensitive delegation flag on privileged accounts | HIGH | — | |
| 18 | SIDHistory on user and computer accounts | CRITICAL–MEDIUM | [T1134.005](https://attack.mitre.org/techniques/T1134/005/) | |
| 19 | GPP passwords in SYSVOL (cpassword) | CRITICAL | [T1552.006](https://attack.mitre.org/techniques/T1552/006/) | |
| 20 | MachineAccountQuota > 0 | HIGH–MEDIUM | [T1136.002](https://attack.mitre.org/techniques/T1136/002/) | |
| 21 | ACL anomalies on domain root, AdminSDHolder, DC OU | CRITICAL | [T1222.001](https://attack.mitre.org/techniques/T1222/001/) | Needs DA |
| 22 | GPO security settings via SYSVOL (no GPMC required) | CRITICAL–MEDIUM | Multiple | |

**Check 22 — GPO security settings** reads `GptTmpl.inf` and `Registry.xml` from every GPO in SYSVOL and performs pattern-based checks for specific high-risk settings:

| Setting checked | Finding if... | MITRE |
|---|---|---|
| WDigest (`UseLogonCredential`) | = 1 | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |
| NTLMv1 (`LmCompatibilityLevel`) | < 3 | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) |
| LM hash storage (`NoLMHash`) | = 0 | [T1110.002](https://attack.mitre.org/techniques/T1110/002/) |
| SMB signing — client + server | Disabled | [T1557.001](https://attack.mitre.org/techniques/T1557/001/) |
| Windows Firewall | Disabled | — |
| Windows Defender | Disabled | — |
| Anonymous access (`RestrictAnonymous`) | = 0 | [T1135](https://attack.mitre.org/techniques/T1135/) |
| SeDebugPrivilege | Non-admin principals | [T1134.001](https://attack.mitre.org/techniques/T1134/001/) |
| AutoRun (`NoDriveTypeAutoRun`) | < 255 | — |
| PowerShell Execution Policy | Unrestricted / Bypass | — |

### Lite mode — 9 checks

Checks **2, 3, 5, 6, 7, 9, 19, 20, 21**. Covers Golden Ticket, Kerberoasting, AS-REP, DCSync, GPP credentials, RBCD, unconstrained delegation, ACL abuse. No full user/computer enumeration. Suitable for large domains or scheduled weekly runs.

---

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Server` | String | PDC Emulator | DC FQDN or IP. Required when running from a non-domain machine |
| `-Credential` | PSCredential | Current user | Explicit credentials for non-domain or cross-domain runs |
| `-OutputPath` | String | Script dir | Full path for HTML report |
| `-CsvPath` | String | Script dir | Full path for CSV export |
| `-StaleAccountDays` | Int | 90 | Logon inactivity threshold for user accounts |
| `-StaleComputerDays` | Int | 90 | Logon inactivity threshold for computer accounts |
| `-LiteMode` | Switch | Off | Run 9 critical checks only |
| `-CheckLAPS` | Switch | Off | Include LAPS coverage check (slow on large domains) |

---

## Estimated runtime

| Domain size | Users | Full mode | Lite mode |
|-------------|-------|-----------|-----------|
| Small | < 500 | ~1 min | ~20 sec |
| Medium | 500–5k | ~3–5 min | ~45 sec |
| Large | 5k–20k | ~8–15 min | ~1–2 min |
| Very large | 20k+ | ~20–35 min | ~2–5 min |

`-CheckLAPS` adds ~5–10 min on domains with 10k+ computers and is therefore off by default.

---

## Known limitations

- Findings should be reviewed in context — not all flagged configurations represent immediate risk. A stale account is not automatically a compromise; MAQ > 0 is not an active exploit. Use findings as a prioritised investigation list, not a verdict
- `LastLogonDate` replicates on a ~14-day best-effort cycle. Stale account findings may include accounts that logged in recently on a different DC
- Checks 9 and 21 require Domain Admin or equivalent read rights. Both skip gracefully if permissions are insufficient
- Severity thresholds (90-day stale, 365-day password age, etc.) are configurable starting points — review findings in context before acting
- Does not detect ADCS misconfigurations, attack chains, shadow credentials, or hybrid/Azure AD issues

---

## Contributing

Issues and pull requests are welcome. If you want to suggest a new check, open an issue describing the misconfiguration and a real-world abuse scenario for it.

---

## Disclaimer

Use only in environments you are authorised to audit.

---

*Part of the [ZavetSec](https://github.com/zavetsec) DFIR toolkit.*
