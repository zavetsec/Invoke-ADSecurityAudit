# Invoke-ADSecurityAudit

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue?logo=powershell)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)
![Read Only](https://img.shields.io/badge/AD%20access-read--only-important)

> **Fastest way to identify exploitable Active Directory misconfigurations in production environments — no setup required.**

Single-file PowerShell script for fast, safe, read-only Active Directory security assessment.  
Run it. Get an actionable HTML report. No setup, no agents, no graph databases.

---

## Preview

![HTML Report — risk overview and findings table](docs/report.png)

![Severity filtering and MITRE ATT&CK mapping](docs/report-filter.png)

---

## Why Invoke-ADSecurityAudit?

| | This tool | BloodHound | PingCastle |
|---|---|---|---|
| Setup required | ❌ None | ✅ Neo4j + agent | ✅ Install |
| Read-only | ✅ | ❌ | ✅ |
| Offline report | ✅ Single HTML | ❌ | ✅ |
| MITRE ATT&CK mapping | ✅ | ✅ | ❌ |
| Lite mode for large domains | ✅ | ❌ | ❌ |
| Zero dependencies | ✅ | ❌ | ❌ |

No infrastructure to deploy. No data leaving the domain. Results in minutes.  
Designed for analysts who need to assess a domain quickly and safely — during incident response, before a pentest, or as part of a periodic review.

---

## What this is NOT

- Not a vulnerability scanner
- Not a continuous monitoring platform
- Not a replacement for BloodHound or full AD assessments

This tool is built for **fast, safe, point-in-time security evaluation**. It finds the misconfigurations that matter most and tells you exactly how to fix them.

---

## Philosophy

It focuses on:
- misconfigurations that are **actively abused in real-world attacks**
- **signal over noise** — findings that require remediation, not theoretical edge cases
- **fast, repeatable assessments** without infrastructure or persistent agents

The risk score is a prioritization aid, not a compliance metric. Not all findings are equal.

---

## Design Principles

- **Read-only by design** — no modification of AD objects under any conditions, ever
- **Exploitable over theoretical** — checks target attack paths observed in real intrusions, mapped to MITRE ATT&CK
- **Deterministic output** — no heuristics that inflate or suppress risk; same environment always produces the same findings
- **Graceful degradation** — insufficient permissions never crash the script; affected checks warn and skip

---

## Use Cases

- **Incident response triage** — identify immediately exploitable attack paths in minutes
- **Pre-pentest baseline** — find the low-hanging fruit before the red team does
- **Internal AD audit** — structured findings with evidence and remediation guidance
- **Continuous hygiene** — schedule Lite mode weekly, Full mode monthly
- **Blue team hardening validation** — verify that mitigations actually took effect

---

## Quick Start

```powershell
# Clone
git clone https://github.com/zavetsec/Invoke-ADSecurityAudit
cd Invoke-ADSecurityAudit

# Lite mode — prioritizes immediately exploitable attack paths, ~2–5 min
.\Invoke-ADSecurityAudit.ps1 -LiteMode

# Full audit — 21 checks, complete coverage
.\Invoke-ADSecurityAudit.ps1
```

The HTML report opens automatically on completion.

---

## Example Finding

Real example from a typical enterprise environment:

```
[CRITICAL] Kerberoastable account with weak encryption

  Account      : svc_sql
  SPN          : MSSQLSvc/sql01.corp.local
  Encryption   : RC4 only (no AES)
  Password age : 847 days
  Privileged   : No

  Risk         : Service ticket can be requested by any domain user and cracked offline
  TTP          : T1558.003 — Kerberoasting

  Recommendation: Enforce AES-256 Kerberos encryption on the account;
                  rotate password to 25+ chars; consider migrating to gMSA
```

This is one finding out of 21 checks. The HTML report presents all findings with the same level of detail, filterable by severity, category, and keyword.

---

## Installation

No installation required. Clone and run.

**Tested on:**
- Windows Server 2016, 2019, 2022
- Windows 10 / 11 with RSAT

**Requires RSAT ActiveDirectory module:**

```powershell
# Windows Server
Add-WindowsFeature RSAT-AD-PowerShell

# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools
```

---

## Features

- **21 security checks** covering the most common AD attack vectors
- **Lite mode** (`-LiteMode`) — prioritizes immediately exploitable attack paths, designed for large domains (10k+ objects), ~2–5 min runtime
- **Risk score** — simple, explainable prioritization model (`CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1`), designed to focus remediation effort where it matters most
- **Read-only** — no changes to AD, no remote execution, no writes of any kind
- **No agent, no install** — standard RSAT `ActiveDirectory` module only
- **Self-contained HTML report** — dark-themed, filterable/sortable table with severity badges and MITRE ATT&CK TTP references
- **CSV export** — structured findings for SIEM ingestion or ticketing
- **MITRE ATT&CK mapping** — all checks mapped to relevant techniques where applicable

---

## Checks

### Full mode — 21 checks

All checks are mapped to MITRE ATT&CK techniques where applicable.

| # | Check | Severity | MITRE TTP |
|---|-------|----------|-----------|
| 1 | Domain / Forest Functional Level | HIGH | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| 2 | Privileged group membership (DA, EA, SA, BA + 6 more) | CRITICAL–MEDIUM | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| 3 | KRBTGT password age — Golden Ticket risk | CRITICAL–MEDIUM | [T1558.001](https://attack.mitre.org/techniques/T1558/001/) |
| 4 | Default Domain Password Policy + Fine-Grained Policies | CRITICAL–MEDIUM | — |
| 5 | Kerberoastable accounts (SPN + weak encryption) | CRITICAL–MEDIUM | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| 6 | AS-REP Roastable accounts (pre-auth disabled) | CRITICAL–HIGH | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| 7 | Unconstrained + constrained delegation with protocol transition | CRITICAL–HIGH | [T1558](https://attack.mitre.org/techniques/T1558/) |
| 8 | AdminSDHolder orphans (AdminCount=1 outside priv groups) | HIGH | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |
| 9 | DCSync rights — replication ACEs on domain root | CRITICAL | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) |
| 10 | Stale and never-logged-on user accounts | HIGH–LOW | [T1078](https://attack.mitre.org/techniques/T1078/) |
| 11 | Password flags (NeverExpires, reversible encryption, DES-only) | CRITICAL–HIGH | [T1078](https://attack.mitre.org/techniques/T1078/) |
| 12 | LAPS deployment coverage | HIGH–MEDIUM | — |
| 13 | Stale computer accounts + end-of-life operating systems | CRITICAL–LOW | — |
| 14 | Domain trust issues (SID filtering, selective auth) | CRITICAL–MEDIUM | — |
| 15 | GPO issues (disabled settings, unlinked GPOs) | LOW | — |
| 16 | Protected Users group coverage for privileged accounts | HIGH | — |
| 17 | Sensitive delegation flag missing on privileged accounts | HIGH | — |
| 18 | SIDHistory on user and computer accounts | CRITICAL–MEDIUM | [T1134.005](https://attack.mitre.org/techniques/T1134/005/) |
| 19 | GPP passwords in SYSVOL (`cpassword` / Groups.xml) | CRITICAL | [T1552.006](https://attack.mitre.org/techniques/T1552/006/) |
| 20 | MachineAccountQuota > 0 — RBCD attack surface | HIGH–MEDIUM | [T1136.002](https://attack.mitre.org/techniques/T1136/002/) |
| 21 | ACL anomalies on domain root, AdminSDHolder, DC OU, privileged objects | CRITICAL | [T1222.001](https://attack.mitre.org/techniques/T1222/001/) |

### Lite mode — 9 checks

Checks **2, 3, 5, 6, 7, 9, 19, 20, 21** — Golden Ticket, Kerberoasting, AS-REP, DCSync, GPP credentials, RBCD, unconstrained delegation, ACL abuse. No full user/computer enumeration. Suitable for quick triage, large domains, or scheduled weekly runs.

---

## Usage

```powershell
# Full audit — PDC Emulator, report to Desktop
.\Invoke-ADSecurityAudit.ps1

# Lite mode — prioritized critical checks
.\Invoke-ADSecurityAudit.ps1 -LiteMode

# Target a specific DC
.\Invoke-ADSecurityAudit.ps1 -Server dc01.corp.local

# Custom stale threshold + specific output path
.\Invoke-ADSecurityAudit.ps1 -StaleAccountDays 60 -OutputPath C:\Reports\ad_audit.html

# Lite mode on large domain
.\Invoke-ADSecurityAudit.ps1 -LiteMode -Server dc01.corp.local -OutputPath C:\Reports\lite.html
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Server` | String | PDC Emulator | Domain controller FQDN to query |
| `-OutputPath` | String | Desktop | Full path for HTML report |
| `-CsvPath` | String | Desktop | Full path for CSV findings export |
| `-StaleAccountDays` | Int | 90 | Days without logon to flag user as stale |
| `-StaleComputerDays` | Int | 90 | Days without logon to flag computer as stale |
| `-LiteMode` | Switch | Off | Run 9 critical checks only |

---

## Estimated runtime

| Domain size | Users | Full mode | Lite mode |
|-------------|-------|-----------|-----------|
| Small | < 500 | ~1 min | ~20 sec |
| Medium | 500–5k | ~3–5 min | ~45 sec |
| Large | 5k–20k | ~8–15 min | ~1–2 min |
| Very large | 20k+ | ~20–35 min | ~2–5 min |

All queries use server-side LDAP filtering. Runtime depends on DC hardware, network latency, GPO/OU complexity, and group nesting depth.

---

## Output

### HTML report — single self-contained file

No external dependencies. Works fully offline.

- Risk level banner with risk score
- Severity stat badges (CRITICAL / HIGH / MEDIUM / LOW / total)
- Domain info panel: functional level, PDC, DN, scan time, mode
- Findings-by-category breakdown with proportion bars
- Full findings table: severity badge, category, MITRE TTP, check name, description, affected objects, evidence, remediation
- Quick-filter buttons: CRITICAL, HIGH, Kerberos, Password, Privileged
- Free-text search across all fields

### CSV export

All findings in structured CSV: `Time, Category, Severity, Check, TTP, Description, AffectedObjects, Evidence, Recommendation`

---

## DC load profile

The script is **100% read-only**. It generates standard LDAP queries comparable to normal workstation domain activity. No `Set-AD*`, `New-AD*`, or `Remove-AD*` operations are used anywhere.

- **Negligible load:** single-object lookups (KRBTGT, domain root, MAQ, SYSVOL file reads)
- **Moderate load:** filtered user/computer enumeration — Full mode only, checks 10–13
- **ACL reads:** `Get-ACL` on up to ~13 specific DN paths (check 21)

Safe to run during business hours. For very large domains in Full mode, off-peak is still recommended.

---

## Notes

- `LastLogonDate` is replicated on a best-effort basis (~14-day cycle). Accounts may appear stale even if recently active on a different DC.
- Checks 9 and 21 require elevated AD read permissions. Without them both skip gracefully with a warning.
- Check 15 (GPO) requires the Group Policy Management Console (GPMC) module. Skipped with a warning if absent.
- LAPS check uses legacy `ms-Mcs-AdmPwdExpirationTime`. Windows LAPS (2023+) uses a different schema attribute — extend if needed.

---

## Contributing

Issues and pull requests are welcome. Suggestions for new checks are especially appreciated — open an issue describing the misconfiguration and its real-world abuse potential.

---

## Disclaimer

Use only in environments you are authorized to audit.

---

*Part of the [ZavetSec](https://github.com/zavetsec) DFIR toolkit — focused on fast, no-deploy security assessment.*
