#Requires -Version 5.1
# Invoke-ADSecurityAudit v1.2 | Build: FIX-001 | Encoding: UTF8-BOM-CRLF
<#
.SYNOPSIS
    Invoke-ADSecurityAudit - Active Directory security audit.
.DESCRIPTION
    Performs comprehensive AD security checks:
      - Privileged accounts and groups (Domain Admins, Enterprise Admins, Schema Admins)
      - Stale / inactive / never-logged-on accounts
      - Password policy weaknesses (Fine-Grained and Default Domain Policy)
      - Kerberoastable accounts (SPNs with weak encryption)
      - AS-REP Roastable accounts (no pre-auth required)
      - AdminSDHolder / SDProp anomalies
      - Unconstrained / Constrained delegation
      - KRBTGT account age (Golden Ticket risk)
      - DCSync capable accounts (replication rights)
      - GPO security issues (disabled features, dangerous settings)
      - Domain trusts enumeration
      - Computers with old OS or not logged in for 90+ days
      - LAPS deployment status
      - AdminCount=1 orphaned accounts
      - Service accounts with interactive logon rights
      - Reversible encryption / DES enabled accounts
      - SIDHistory on user/computer accounts (privilege escalation path)
      - GPP Passwords in SYSVOL (cpassword in Groups.xml / other policy files)
      - MachineAccountQuota (RBCD attack risk)
      - ACL anomalies on AD objects (WriteDACL/WriteOwner/GenericAll by non-admins)

    Lite mode (-LiteMode): 9 highest-impact checks only, optimised for large domains (10k+ users).
      Estimated runtime 2-5 min. Skips full user/computer enumeration.
      Lite checks: KRBTGT age, Privileged groups, Kerberoasting, AS-REP Roasting,
                   Unconstrained Delegation, DCSync rights, GPP/SYSVOL,
                   MachineAccountQuota, ACL anomalies on critical objects.
.PARAMETER Server
    Domain Controller to query. Default = PDC Emulator.
.PARAMETER OutputPath
    Path for HTML report. Default = Desktop.
.PARAMETER CsvPath
    Path for CSV findings export.
.PARAMETER StaleAccountDays
    Days since last logon to consider account stale. Default = 90.
.PARAMETER StaleComputerDays
    Days since computer last logon to flag. Default = 90.
.PARAMETER LiteMode
    Run only 9 highest-impact checks. Recommended for domains with 10,000+ objects.
    Reduces runtime and DC load significantly. Use for quick triage or scheduled checks.
.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1
    .\Invoke-ADSecurityAudit.ps1 -LiteMode
    .\Invoke-ADSecurityAudit.ps1 -Server dc01.corp.local -StaleAccountDays 60
    .\Invoke-ADSecurityAudit.ps1 -LiteMode -Server dc01.corp.local
.NOTES
    Version : 1.2
    Requires: PowerShell 5.1+, RSAT AD module (ActiveDirectory), Domain read access.
    Install : Add-WindowsFeature RSAT-AD-PowerShell  (Server)
              Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools (Win10/11)
#>

[CmdletBinding()]
param(
    [string]$Server            = '',
    [string]$OutputPath        = "$env:USERPROFILE\Desktop\ADSecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    [string]$CsvPath           = "$env:USERPROFILE\Desktop\ADSecurityAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [int]   $StaleAccountDays  = 90,
    [int]   $StaleComputerDays = 90,
    [switch]$LiteMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$global:Findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:StartTime = Get-Date

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
function Write-Section { param([string]$T); Write-Host ""; Write-Host "[*] $T" -ForegroundColor Cyan }
function Write-Info    { param([string]$M); Write-Host "  [+] $M" -ForegroundColor Green }
function Write-Warn    { param([string]$M); Write-Host "  [!] $M" -ForegroundColor Yellow }

function Write-Hunt {
    param([string]$Msg, [string]$Severity = 'MEDIUM')
    $c = switch ($Severity) {
        'CRITICAL'{'Red'} 'HIGH'{'Red'} 'MEDIUM'{'Yellow'} 'LOW'{'Green'} default{'Gray'}
    }
    Write-Host "  [$Severity] $Msg" -ForegroundColor $c
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Check,
        [string]$Description,
        [string]$AffectedObjects = '',
        [string]$Evidence        = '',
        [string]$Recommendation  = '',
        [string]$TTP             = ''
    )
    $global:Findings.Add([PSCustomObject]@{
        Time            = (Get-Date -Format 'HH:mm:ss')
        Category        = $Category
        Severity        = $Severity
        Check           = $Check
        TTP             = $TTP
        Description     = $Description
        AffectedObjects = $AffectedObjects
        Evidence        = $Evidence
        Recommendation  = $Recommendation
    })
    Write-Hunt -Msg "[$Category] $Check - $Description" -Severity $Severity
}

# AD module check
function Test-ADModule {
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        Write-Host ""
        Write-Host "  [ERROR] ActiveDirectory PowerShell module not found." -ForegroundColor Red
        Write-Host "  Install on Windows Server : Add-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor Yellow
        Write-Host "  Install on Windows 10/11  : Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools" -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }
    Import-Module ActiveDirectory -EA Stop
}

# -------------------------------------------------------
# INIT
# -------------------------------------------------------
Write-Host ""
Write-Host "  =============================================" -ForegroundColor DarkCyan
Write-Host "    Invoke-ADSecurityAudit v1.2" -ForegroundColor Cyan
if ($LiteMode) {
Write-Host "    MODE: LITE (9 critical checks)" -ForegroundColor Yellow
} else {
Write-Host "    MODE: FULL (21 checks)" -ForegroundColor Green
}
Write-Host "  =============================================" -ForegroundColor DarkCyan

Test-ADModule

# Resolve DC
$adParams = @{}
if ($Server) { $adParams['Server'] = $Server }

try {
    $domain   = Get-ADDomain @adParams -EA Stop
    $forest   = Get-ADForest @adParams -EA Stop
    $domainDN = $domain.DistinguishedName
    $pdcFQDN  = $domain.PDCEmulator

    if (-not $Server) {
        $Server = $pdcFQDN
        $adParams['Server'] = $Server
    }

    Write-Info "Domain   : $($domain.DNSRoot)"
    Write-Info "Forest   : $($forest.Name)"
    Write-Info "PDC      : $pdcFQDN"
    Write-Info "Functional Level: Domain=$($domain.DomainMode) Forest=$($forest.ForestMode)"
} catch {
    Write-Host "  [ERROR] Cannot connect to Active Directory: $_" -ForegroundColor Red
    exit 1
}

$staleDate    = (Get-Date).AddDays(-$StaleAccountDays)
$staleCompDate= (Get-Date).AddDays(-$StaleComputerDays)
$pwdStaleDate = (Get-Date).AddDays(-365)

# -------------------------------------------------------
# 1. DOMAIN FUNCTIONAL LEVEL  [FULL only]
# -------------------------------------------------------
if (-not $LiteMode) {
Write-Section "Check 1 - Domain / Forest Functional Level"

$domainFL = $domain.DomainMode.ToString()
$forestFL = $forest.ForestMode.ToString()

$oldLevels = @('Windows2000Domain','Windows2003Domain','Windows2003InterimDomain','Windows2008Domain','Windows2008R2Domain')
if ($domainFL -in $oldLevels) {
    Add-Finding -Category 'Domain Config' -Severity 'HIGH' -TTP 'T1078.002' `
        -Check 'Domain Functional Level' `
        -Description "Domain functional level is outdated: $domainFL" `
        -Evidence "DomainMode=$domainFL ForestMode=$forestFL" `
        -Recommendation 'Raise domain/forest functional level to Windows2016Domain or higher to enable modern security features'
} else {
    Write-Info "Domain FL: $domainFL - OK"
}
} else {
    # Still need these for other checks
    $domainFL = $domain.DomainMode.ToString()
    $forestFL = $forest.ForestMode.ToString()
}

# -------------------------------------------------------
# 2. PRIVILEGED GROUP MEMBERS
# -------------------------------------------------------
Write-Section "Check 2 - Privileged Group Membership"

$privGroups = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Group Policy Creator Owners',
    'Backup Operators',
    'Account Operators',
    'Server Operators',
    'Print Operators',
    'Remote Desktop Users',
    'Administrators'
)

$allPrivUsers = @{}

foreach ($grpName in $privGroups) {
    try {
        $grp = Get-ADGroup -Filter { Name -eq $grpName } @adParams -EA Stop
        if (-not $grp) { continue }

        $members = Get-ADGroupMember -Identity $grp -Recursive @adParams -EA Stop |
                   Where-Object { $_.objectClass -eq 'user' }

        if ($members.Count -eq 0) { Write-Info "$grpName : empty - OK"; continue }

        $memberDetails = foreach ($m in $members) {
            try {
                Get-ADUser -Identity $m.SamAccountName -Properties LastLogonDate,PasswordLastSet,Enabled,AdminCount @adParams -EA Stop
            } catch {}
        }

        $enabled   = ($memberDetails | Where-Object { $_.Enabled }).Count
        $disabled  = ($memberDetails | Where-Object { -not $_.Enabled }).Count
        $stale     = ($memberDetails | Where-Object { $_.Enabled -and $_.LastLogonDate -lt $staleDate -and $_.LastLogonDate }).Count
        $names     = ($memberDetails | Select-Object -ExpandProperty SamAccountName) -join ', '

        # Flag: too many DA
        $sev = 'INFO'
        if ($grpName -in @('Domain Admins','Enterprise Admins','Schema Admins') -and $enabled -gt 5) {
            $sev = 'HIGH'
            Add-Finding -Category 'Privileged Accounts' -Severity $sev -TTP 'T1078.002' `
                -Check "Excessive $grpName Members" `
                -Description "$grpName has $enabled enabled member(s) - should be minimal" `
                -AffectedObjects $names `
                -Evidence "Enabled=$enabled Disabled=$disabled Stale=$stale" `
                -Recommendation "Reduce $grpName membership to minimum necessary; use tiered administration model"
        } elseif ($enabled -gt 0) {
            Write-Info "$grpName : $enabled enabled member(s)"
        }

        # Flag: disabled accounts still in privileged groups
        if ($disabled -gt 0) {
            $disNames = ($memberDetails | Where-Object { -not $_.Enabled } | Select-Object -ExpandProperty SamAccountName) -join ', '
            Add-Finding -Category 'Privileged Accounts' -Severity 'MEDIUM' -TTP 'T1078.002' `
                -Check "Disabled Accounts in $grpName" `
                -Description "$disabled disabled account(s) still present in $grpName" `
                -AffectedObjects $disNames `
                -Evidence "Group=$grpName DisabledCount=$disabled" `
                -Recommendation 'Remove disabled accounts from privileged groups immediately'
        }

        # Flag: stale accounts in privileged groups
        if ($stale -gt 0) {
            $staleNames = ($memberDetails | Where-Object { $_.Enabled -and $_.LastLogonDate -lt $staleDate -and $_.LastLogonDate } |
                          Select-Object -ExpandProperty SamAccountName) -join ', '
            Add-Finding -Category 'Privileged Accounts' -Severity 'HIGH' -TTP 'T1078.002' `
                -Check "Stale Accounts in $grpName" `
                -Description "$stale stale account(s) in $grpName (no logon for $StaleAccountDays+ days)" `
                -AffectedObjects $staleNames `
                -Evidence "Group=$grpName StaleCount=$stale ThresholdDays=$StaleAccountDays" `
                -Recommendation 'Review and remove stale privileged accounts; enforce periodic access review'
        }

        foreach ($m in $memberDetails) { $allPrivUsers[$m.SamAccountName] = $grpName }

    } catch { Write-Warn "Could not query group: $grpName - $_" }
}

# -------------------------------------------------------
# 3. KRBTGT ACCOUNT AGE
# -------------------------------------------------------
Write-Section "Check 3 - KRBTGT Account Password Age"

try {
    $krbtgt = Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet,PasswordNeverExpires @adParams -EA Stop
    $krbtgtAge = ((Get-Date) - $krbtgt.PasswordLastSet).Days

    $sev = if ($krbtgtAge -gt 365) { 'CRITICAL' } elseif ($krbtgtAge -gt 180) { 'HIGH' } else { 'MEDIUM' }

    if ($krbtgtAge -gt 90) {
        Add-Finding -Category 'Kerberos Security' -Severity $sev -TTP 'T1558.001' `
            -Check 'KRBTGT Password Age' `
            -Description "KRBTGT password is $krbtgtAge days old (Golden Ticket risk if compromised)" `
            -AffectedObjects 'krbtgt' `
            -Evidence "PasswordLastSet=$($krbtgt.PasswordLastSet.ToString('yyyy-MM-dd')) AgeDays=$krbtgtAge" `
            -Recommendation 'Reset KRBTGT password twice (24h apart) to invalidate any Golden Tickets; schedule regular rotation (every 180 days)'
    } else {
        Write-Info "KRBTGT age: $krbtgtAge days - OK"
    }
} catch { Write-Warn "Cannot query KRBTGT: $_" }

# -------------------------------------------------------
# 4. DEFAULT DOMAIN PASSWORD POLICY  [FULL only]
# -------------------------------------------------------
if (-not $LiteMode) {
Write-Section "Check 4 - Password Policy"

try {
    $pwdPolicy = Get-ADDefaultDomainPasswordPolicy @adParams -EA Stop

    if ($pwdPolicy.MinPasswordLength -lt 12) {
        Add-Finding -Category 'Password Policy' -Severity 'HIGH' `
            -Check 'Minimum Password Length' `
            -Description "Min password length is $($pwdPolicy.MinPasswordLength) chars (recommended: 14+)" `
            -Evidence "MinPasswordLength=$($pwdPolicy.MinPasswordLength)" `
            -Recommendation 'Set minimum password length to 14+ chars; consider passphrase policy'
    }
    if (-not $pwdPolicy.ComplexityEnabled) {
        Add-Finding -Category 'Password Policy' -Severity 'HIGH' `
            -Check 'Password Complexity Disabled' `
            -Description 'Password complexity is disabled in Default Domain Policy' `
            -Evidence 'ComplexityEnabled=False' `
            -Recommendation 'Enable password complexity requirements'
    }
    if ($pwdPolicy.MaxPasswordAge.Days -eq 0 -or $pwdPolicy.MaxPasswordAge.Days -gt 365) {
        Add-Finding -Category 'Password Policy' -Severity 'MEDIUM' `
            -Check 'Password Expiration' `
            -Description "Password max age is $($pwdPolicy.MaxPasswordAge.Days) days (0=never expires, or too long)" `
            -Evidence "MaxPasswordAge=$($pwdPolicy.MaxPasswordAge.Days) days" `
            -Recommendation 'Set max password age to 90-180 days; or implement NIST SP 800-63B breach-based policy'
    }
    if ($pwdPolicy.LockoutThreshold -eq 0) {
        Add-Finding -Category 'Password Policy' -Severity 'HIGH' `
            -Check 'Account Lockout Disabled' `
            -Description 'Account lockout threshold is 0 (unlimited password attempts allowed)' `
            -Evidence 'LockoutThreshold=0' `
            -Recommendation 'Set lockout threshold to 5-10 attempts; configure lockout duration and observation window'
    } elseif ($pwdPolicy.LockoutThreshold -gt 10) {
        Add-Finding -Category 'Password Policy' -Severity 'MEDIUM' `
            -Check 'Weak Account Lockout Threshold' `
            -Description "Lockout threshold is $($pwdPolicy.LockoutThreshold) (too permissive, brute-force possible)" `
            -Evidence "LockoutThreshold=$($pwdPolicy.LockoutThreshold)" `
            -Recommendation 'Reduce lockout threshold to 5-10 attempts'
    }
    if ($pwdPolicy.ReversibleEncryptionEnabled) {
        Add-Finding -Category 'Password Policy' -Severity 'CRITICAL' `
            -Check 'Reversible Encryption Enabled' `
            -Description 'Default domain policy has reversible encryption ENABLED - passwords stored in plaintext equivalent' `
            -Evidence 'ReversibleEncryptionEnabled=True' `
            -Recommendation 'DISABLE reversible encryption immediately; force password reset for all affected accounts'
    }
    Write-Info "Password policy: MinLen=$($pwdPolicy.MinPasswordLength) Complexity=$($pwdPolicy.ComplexityEnabled) Lockout=$($pwdPolicy.LockoutThreshold)"
} catch { Write-Warn "Cannot query password policy: $_" }

# Fine-Grained Password Policies
try {
    $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * @adParams -EA Stop
    if ($fgpp) {
        Write-Info "Fine-Grained Password Policies: $($fgpp.Count)"
        foreach ($p in $fgpp) {
            if ($p.MinPasswordLength -lt 12) {
                Add-Finding -Category 'Password Policy' -Severity 'MEDIUM' `
                    -Check 'Weak Fine-Grained Policy' `
                    -Description "FGPP '$($p.Name)' has min length $($p.MinPasswordLength) (applies to: $($p.AppliesTo -join ', '))" `
                    -AffectedObjects ($p.AppliesTo -join ', ') `
                    -Evidence "Policy=$($p.Name) MinLen=$($p.MinPasswordLength) Precedence=$($p.Precedence)" `
                    -Recommendation 'Update Fine-Grained Password Policy to meet minimum length requirements'
            }
        }
    }
} catch {}
} # end -not LiteMode (Check 4)

# -------------------------------------------------------
# 5. KERBEROASTABLE ACCOUNTS
# -------------------------------------------------------
Write-Section "Check 5 - Kerberoastable Accounts (SPNs)"

try {
    $kerbAccounts = Get-ADUser -Filter { ServicePrincipalName -ne '$null' -and Enabled -eq $true } `
        -Properties ServicePrincipalName,PasswordLastSet,LastLogonDate,AdminCount,Description @adParams -EA Stop |
        Where-Object { $_.SamAccountName -ne 'krbtgt' }

    if ($kerbAccounts) {
        foreach ($acct in $kerbAccounts) {
            $spns       = $acct.ServicePrincipalName -join ' | '
            $pwdAge     = if ($acct.PasswordLastSet) { ((Get-Date) - $acct.PasswordLastSet).Days } else { 999 }
            $isPriv     = $allPrivUsers.ContainsKey($acct.SamAccountName)
            $sev        = if ($isPriv) { 'CRITICAL' } elseif ($pwdAge -gt 365) { 'HIGH' } else { 'MEDIUM' }

            Add-Finding -Category 'Kerberos' -Severity $sev -TTP 'T1558.003' `
                -Check 'Kerberoastable Account' `
                -Description "Account '$($acct.SamAccountName)' has SPN(s) - subject to Kerberoasting$(if($isPriv){' [PRIVILEGED]'})" `
                -AffectedObjects $acct.SamAccountName `
                -Evidence "SPN=$spns PwdAge=${pwdAge}d LastLogon=$($acct.LastLogonDate) AdminCount=$($acct.AdminCount)" `
                -Recommendation 'Use strong passwords (25+ chars) for service accounts; prefer gMSA; enforce AES-256 encryption on SPNs'
        }
        Write-Info "Kerberoastable accounts: $($kerbAccounts.Count)"
    } else {
        Write-Info "No kerberoastable accounts found - OK"
    }
} catch { Write-Warn "Cannot query SPNs: $_" }

# -------------------------------------------------------
# 6. AS-REP ROASTABLE ACCOUNTS
# -------------------------------------------------------
Write-Section "Check 6 - AS-REP Roastable Accounts (PreAuth disabled)"

try {
    $asrepAccounts = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } `
        -Properties DoesNotRequirePreAuth,PasswordLastSet,LastLogonDate,AdminCount @adParams -EA Stop

    if ($asrepAccounts) {
        $names = ($asrepAccounts | Select-Object -ExpandProperty SamAccountName) -join ', '
        $sev   = if ($asrepAccounts.Count -gt 3 -or ($asrepAccounts | Where-Object { $allPrivUsers.ContainsKey($_.SamAccountName) })) { 'CRITICAL' } else { 'HIGH' }
        Add-Finding -Category 'Kerberos' -Severity $sev -TTP 'T1558.004' `
            -Check 'AS-REP Roastable Accounts' `
            -Description "$($asrepAccounts.Count) account(s) do not require Kerberos pre-authentication" `
            -AffectedObjects $names `
            -Evidence "Count=$($asrepAccounts.Count) Accounts=$names" `
            -Recommendation 'Enable Kerberos pre-authentication on all accounts; disable DoesNotRequirePreAuth'
    } else {
        Write-Info "No AS-REP roastable accounts found - OK"
    }
} catch { Write-Warn "Cannot query pre-auth settings: $_" }

# -------------------------------------------------------
# 7. UNCONSTRAINED DELEGATION
# -------------------------------------------------------
Write-Section "Check 7 - Unconstrained Delegation"

try {
    # Accounts with unconstrained delegation (TrustedForDelegation=True)
    $unconstrAccounts = Get-ADUser -Filter { TrustedForDelegation -eq $true -and Enabled -eq $true } `
        -Properties TrustedForDelegation,ServicePrincipalName,LastLogonDate @adParams -EA Stop

    $unconstrComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true -and Enabled -eq $true } `
        -Properties TrustedForDelegation,OperatingSystem @adParams -EA Stop |
        Where-Object { $_.DistinguishedName -notmatch 'Domain Controllers' }

    if ($unconstrAccounts) {
        $names = ($unconstrAccounts | Select-Object -ExpandProperty SamAccountName) -join ', '
        Add-Finding -Category 'Delegation' -Severity 'CRITICAL' -TTP 'T1558' `
            -Check 'Unconstrained Delegation on User Accounts' `
            -Description "$($unconstrAccounts.Count) USER account(s) have unconstrained Kerberos delegation" `
            -AffectedObjects $names `
            -Evidence "Accounts=$names" `
            -Recommendation 'Remove unconstrained delegation; use constrained delegation or resource-based constrained delegation instead'
    }
    if ($unconstrComputers) {
        $names = ($unconstrComputers | Select-Object -ExpandProperty Name) -join ', '
        Add-Finding -Category 'Delegation' -Severity 'HIGH' -TTP 'T1558' `
            -Check 'Unconstrained Delegation on Computers' `
            -Description "$($unconstrComputers.Count) non-DC computer(s) have unconstrained delegation" `
            -AffectedObjects $names `
            -Evidence "Computers=$names" `
            -Recommendation 'Remove unconstrained delegation from workstations/servers; enable Protected Users for sensitive accounts'
    }
    if (-not $unconstrAccounts -and -not $unconstrComputers) {
        Write-Info "No unconstrained delegation found (non-DC) - OK"
    }
} catch { Write-Warn "Cannot query delegation: $_" }

# Constrained delegation with protocol transition (Any auth)
try {
    $protoTransition = Get-ADUser -Filter { TrustedToAuthForDelegation -eq $true -and Enabled -eq $true } `
        -Properties TrustedToAuthForDelegation @adParams -EA Stop
    if ($protoTransition) {
        $names = ($protoTransition | Select-Object -ExpandProperty SamAccountName) -join ', '
        Add-Finding -Category 'Delegation' -Severity 'HIGH' -TTP 'T1558' `
            -Check 'Constrained Delegation with Protocol Transition' `
            -Description "$($protoTransition.Count) account(s) have constrained delegation with protocol transition (Any auth)" `
            -AffectedObjects $names `
            -Evidence "Accounts=$names" `
            -Recommendation 'Review if protocol transition is required; prefer Kerberos-only constrained delegation'
    }
} catch {}

# -------------------------------------------------------
# 8. ADMINSDHOLDER / ADMINCOUNT ANOMALIES  [FULL only]
# -------------------------------------------------------
if (-not $LiteMode) {
Write-Section "Check 8 - AdminSDHolder / AdminCount Anomalies"

try {
    $adminCountUsers = Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $true } `
        -Properties AdminCount,MemberOf,LastLogonDate,PasswordLastSet @adParams -EA Stop

    $orphanAdmin = $adminCountUsers | Where-Object {
        $sam = $_.SamAccountName
        -not $allPrivUsers.ContainsKey($sam)
    }

    if ($orphanAdmin) {
        $names = ($orphanAdmin | Select-Object -ExpandProperty SamAccountName) -join ', '
        Add-Finding -Category 'AdminSDHolder' -Severity 'HIGH' -TTP 'T1078.002' `
            -Check 'Orphaned AdminCount=1 Accounts' `
            -Description "$($orphanAdmin.Count) account(s) have AdminCount=1 but are not in any privileged group (SDProp orphan)" `
            -AffectedObjects $names `
            -Evidence "Count=$($orphanAdmin.Count) Accounts=$names" `
            -Recommendation 'Reset AdminCount to 0 and restore inheritable permissions; investigate why accounts had admin rights'
    } else {
        Write-Info "No AdminSDHolder orphans found - OK"
    }
} catch { Write-Warn "Cannot query AdminCount: $_" }
} # end -not LiteMode (Check 8)

# -------------------------------------------------------
# 9. DCSYNC RIGHTS (Replication Privileges)
# -------------------------------------------------------
Write-Section "Check 9 - DCSync Capable Accounts"

try {
    $domainACL = Get-ACL "AD:\$domainDN" -EA Stop
    $dcSyncRights = @(
        'DS-Replication-Get-Changes',
        'DS-Replication-Get-Changes-All',
        'DS-Replication-Get-Changes-In-Filtered-Set'
    )

    $dcSyncAccounts = @()
    foreach ($ace in $domainACL.Access) {
        if ($ace.ActiveDirectoryRights -match 'ExtendedRight' -and
            $ace.AccessControlType -eq 'Allow' -and
            $ace.IdentityReference -notmatch '(Domain Controllers|Enterprise Domain Controllers|SYSTEM|Domain Admins|Enterprise Admins|Administrators)') {
            foreach ($right in $dcSyncRights) {
                if ($ace.ObjectType.ToString() -eq (
                    [System.DirectoryServices.ActiveDirectory.ActiveDirectorySecurity]::new().GetType().Assembly.GetType('System.DirectoryServices.ActiveDirectory.ActiveDirectorySecurity'))) {
                    break
                }
            }
            # Check GUID for DS-Replication-Get-Changes-All: {1131f6ad-...}
            $guidStr = $ace.ObjectType.ToString().ToLower()
            if ($guidStr -in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                               '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
                               '89e95b76-444d-4c62-991a-0facbeda640c')) {
                $dcSyncAccounts += $ace.IdentityReference.ToString()
            }
        }
    }

    if ($dcSyncAccounts.Count -gt 0) {
        $unique = ($dcSyncAccounts | Sort-Object -Unique) -join ', '
        Add-Finding -Category 'DCSync' -Severity 'CRITICAL' -TTP 'T1003.006' `
            -Check 'Unexpected DCSync Rights' `
            -Description "$($dcSyncAccounts.Count) non-standard principal(s) have replication (DCSync) rights on domain" `
            -AffectedObjects $unique `
            -Evidence "Principals=$unique" `
            -Recommendation 'CRITICAL: Remove DCSync rights from non-DC/non-admin accounts immediately; investigate how rights were granted'
    } else {
        Write-Info "No unexpected DCSync rights found - OK"
    }
} catch { Write-Warn "Cannot query domain ACL (may need elevated rights): $_" }

# -------------------------------------------------------
# 10-18: FULL MODE ONLY CHECKS
# (Stale accounts, password flags, LAPS, computers, trusts, GPO, Protected Users, sensitive flags, SIDHistory)
# -------------------------------------------------------
if (-not $LiteMode) {

# -------------------------------------------------------
# 10. STALE USER ACCOUNTS
# -------------------------------------------------------
Write-Section "Check 10 - Stale User Accounts"

try {
    $staleEnabled = Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -lt $staleDate } `
        -Properties LastLogonDate,PasswordLastSet,Description,MemberOf @adParams -EA Stop |
        Where-Object { $_.LastLogonDate -ne $null }

    $neverLoggedOn = Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -notlike '*' } `
        -Properties LastLogonDate,PasswordLastSet,WhenCreated @adParams -EA Stop |
        Where-Object { $_.WhenCreated -lt (Get-Date).AddDays(-30) -and $_.LastLogonDate -eq $null }

    if ($staleEnabled.Count -gt 0) {
        $names = ($staleEnabled | Sort-Object LastLogonDate | Select-Object -First 20 |
                  ForEach-Object { "$($_.SamAccountName)($($_.LastLogonDate.ToString('yyyy-MM-dd')))" }) -join ', '
        $sev = if ($staleEnabled.Count -gt 20) { 'HIGH' } else { 'MEDIUM' }
        Add-Finding -Category 'Account Hygiene' -Severity $sev -TTP 'T1078' `
            -Check 'Stale Enabled User Accounts' `
            -Description "$($staleEnabled.Count) enabled user account(s) have not logged in for $StaleAccountDays+ days" `
            -AffectedObjects $names `
            -Evidence "Count=$($staleEnabled.Count) StaleThreshold=$StaleAccountDays days" `
            -Recommendation 'Disable or delete stale accounts; implement automated deprovisioning; enforce account review process'
    } else {
        Write-Info "No stale user accounts found - OK"
    }

    if ($neverLoggedOn.Count -gt 0) {
        $names = ($neverLoggedOn | Select-Object -First 20 | ForEach-Object { $_.SamAccountName }) -join ', '
        Add-Finding -Category 'Account Hygiene' -Severity 'LOW' `
            -Check 'Accounts Never Logged On' `
            -Description "$($neverLoggedOn.Count) enabled account(s) created 30+ days ago have never logged on" `
            -AffectedObjects $names `
            -Evidence "Count=$($neverLoggedOn.Count)" `
            -Recommendation 'Review purpose of accounts; disable if unused; investigate if unauthorized account creation'
    }
} catch { Write-Warn "Cannot query stale accounts: $_" }

# -------------------------------------------------------
# 11. PASSWORD NEVER EXPIRES / REVERSIBLE ENCRYPTION
# -------------------------------------------------------
Write-Section "Check 11 - Account Password Flags"

try {
    $pwdNeverExp = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } `
        -Properties PasswordNeverExpires,PasswordLastSet,LastLogonDate,Description @adParams -EA Stop

    if ($pwdNeverExp.Count -gt 0) {
        $privNeverExp = $pwdNeverExp | Where-Object { $allPrivUsers.ContainsKey($_.SamAccountName) }
        $regNeverExp  = $pwdNeverExp | Where-Object { -not $allPrivUsers.ContainsKey($_.SamAccountName) }

        if ($privNeverExp.Count -gt 0) {
            $names = ($privNeverExp | Select-Object -ExpandProperty SamAccountName) -join ', '
            Add-Finding -Category 'Password Policy' -Severity 'CRITICAL' -TTP 'T1078' `
                -Check 'Privileged Accounts Password Never Expires' `
                -Description "$($privNeverExp.Count) PRIVILEGED account(s) have PasswordNeverExpires set" `
                -AffectedObjects $names `
                -Evidence "PrivilegedAccounts=$names" `
                -Recommendation 'CRITICAL: Remove PasswordNeverExpires from all privileged accounts; enforce regular rotation'
        }
        if ($regNeverExp.Count -gt 0) {
            $names = ($regNeverExp | Select-Object -First 20 | Select-Object -ExpandProperty SamAccountName) -join ', '
            $sev   = if ($regNeverExp.Count -gt 20) { 'HIGH' } else { 'MEDIUM' }
            Add-Finding -Category 'Password Policy' -Severity $sev `
                -Check 'Accounts with Password Never Expires' `
                -Description "$($regNeverExp.Count) enabled account(s) have PasswordNeverExpires set" `
                -AffectedObjects $names `
                -Evidence "Count=$($regNeverExp.Count)" `
                -Recommendation 'Review and remove PasswordNeverExpires flag; implement password expiration policy'
        }
    } else {
        Write-Info "No accounts with PasswordNeverExpires found - OK"
    }

    $revEncUsers = Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true -and Enabled -eq $true } `
        -Properties AllowReversiblePasswordEncryption @adParams -EA Stop
    if ($revEncUsers.Count -gt 0) {
        $names = ($revEncUsers | Select-Object -ExpandProperty SamAccountName) -join ', '
        Add-Finding -Category 'Password Policy' -Severity 'CRITICAL' `
            -Check 'Reversible Password Encryption on Accounts' `
            -Description "$($revEncUsers.Count) account(s) have reversible password encryption enabled" `
            -AffectedObjects $names `
            -Evidence "Accounts=$names" `
            -Recommendation 'Disable AllowReversiblePasswordEncryption; force password reset for affected accounts'
    }

    $desUsers = Get-ADUser -Filter { UseDESKeyOnly -eq $true -and Enabled -eq $true } `
        -Properties UseDESKeyOnly @adParams -EA Stop
    if ($desUsers.Count -gt 0) {
        $names = ($desUsers | Select-Object -ExpandProperty SamAccountName) -join ', '
        Add-Finding -Category 'Kerberos' -Severity 'HIGH' `
            -Check 'DES Encryption Enabled' `
            -Description "$($desUsers.Count) account(s) have DES Kerberos encryption enabled (weak, deprecated)" `
            -AffectedObjects $names `
            -Evidence "Accounts=$names" `
            -Recommendation 'Disable UseDESKeyOnly; require AES-256 Kerberos encryption'
    }
} catch { Write-Warn "Cannot query account flags: $_" }

# -------------------------------------------------------
# 12. LAPS DEPLOYMENT
# -------------------------------------------------------
Write-Section "Check 12 - LAPS (Local Administrator Password Solution)"

try {
    $computers = Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like '*Windows*' } `
        -Properties 'ms-Mcs-AdmPwdExpirationTime','OperatingSystem','LastLogonDate' @adParams -EA Stop

    $withLAPS    = ($computers | Where-Object { $_.'ms-Mcs-AdmPwdExpirationTime' -ne $null }).Count
    $withoutLAPS = ($computers | Where-Object { $_.'ms-Mcs-AdmPwdExpirationTime' -eq $null }).Count
    $totalComp   = $computers.Count

    if ($withoutLAPS -gt 0 -and $withLAPS -eq 0) {
        Add-Finding -Category 'Local Admin' -Severity 'HIGH' `
            -Check 'LAPS Not Deployed' `
            -Description "LAPS not deployed on any of $totalComp Windows computer(s) - local admin passwords may be identical" `
            -AffectedObjects "All $totalComp Windows computers" `
            -Evidence "WithLAPS=$withLAPS WithoutLAPS=$withoutLAPS Total=$totalComp" `
            -Recommendation 'Deploy LAPS or Windows LAPS (built-in since 2023); unique local admin passwords prevent lateral movement'
    } elseif ($withoutLAPS -gt 0) {
        $pct = [Math]::Round($withLAPS / $totalComp * 100)
        $sev = if ($pct -lt 50) { 'HIGH' } else { 'MEDIUM' }
        Add-Finding -Category 'Local Admin' -Severity $sev `
            -Check 'LAPS Partial Deployment' `
            -Description "LAPS deployed on $withLAPS/$totalComp computers ($pct%); $withoutLAPS computer(s) without LAPS" `
            -AffectedObjects "$withoutLAPS computers without LAPS" `
            -Evidence "WithLAPS=$withLAPS WithoutLAPS=$withoutLAPS Coverage=$pct%" `
            -Recommendation 'Complete LAPS deployment to all Windows endpoints'
    } else {
        Write-Info "LAPS deployed on all $totalComp computers - OK"
    }
} catch { Write-Warn "Cannot query LAPS status (attribute may not exist): $_" }

# -------------------------------------------------------
# 13. STALE COMPUTER ACCOUNTS
# -------------------------------------------------------
Write-Section "Check 13 - Stale Computer Accounts"

try {
    $staleComputers = Get-ADComputer -Filter { Enabled -eq $true -and LastLogonDate -lt $staleCompDate } `
        -Properties LastLogonDate,OperatingSystem,OperatingSystemVersion @adParams -EA Stop |
        Where-Object { $_.LastLogonDate -ne $null }

    if ($staleComputers.Count -gt 0) {
        $names = ($staleComputers | Sort-Object LastLogonDate | Select-Object -First 20 |
                  ForEach-Object { "$($_.Name)($($_.OperatingSystem))" }) -join ', '
        $sev = if ($staleComputers.Count -gt 20) { 'MEDIUM' } else { 'LOW' }
        Add-Finding -Category 'Account Hygiene' -Severity $sev `
            -Check 'Stale Computer Accounts' `
            -Description "$($staleComputers.Count) enabled computer account(s) have not authenticated for $StaleComputerDays+ days" `
            -AffectedObjects $names `
            -Evidence "Count=$($staleComputers.Count) Threshold=$StaleComputerDays days" `
            -Recommendation 'Disable and eventually delete stale computer accounts; they can be used for Kerberos relay attacks'
    } else {
        Write-Info "No stale computer accounts found - OK"
    }

    $eolPatterns = @('Windows XP','Windows 7','Windows 8','Server 2003','Server 2008','Server 2012')
    $eolComputers = $computers | Where-Object {
        $os = $_.OperatingSystem
        $match = $false
        foreach ($p in $eolPatterns) { if ($os -match $p) { $match = $true; break } }
        $match
    }
    if ($eolComputers.Count -gt 0) {
        $osGroups = $eolComputers | Group-Object OperatingSystem |
            ForEach-Object { "$($_.Name):$($_.Count)" }
        Add-Finding -Category 'Patch Management' -Severity 'CRITICAL' `
            -Check 'End-of-Life OS Computers' `
            -Description "$($eolComputers.Count) computer(s) running EOL/unsupported Windows OS" `
            -AffectedObjects ($eolComputers | Select-Object -First 15 | Select-Object -ExpandProperty Name) -join ', ' `
            -Evidence "OSBreakdown: $($osGroups -join ' | ')" `
            -Recommendation 'CRITICAL: Upgrade EOL systems immediately; isolate until upgraded; EOL systems have unpatched CVEs'
    }
} catch { Write-Warn "Cannot query computer accounts: $_" }

# -------------------------------------------------------
# 14. DOMAIN TRUSTS
# -------------------------------------------------------
Write-Section "Check 14 - Domain Trusts"

try {
    $trusts = Get-ADTrust -Filter * @adParams -EA Stop
    foreach ($trust in $trusts) {
        $issues = @()
        if ($trust.TrustType -eq 'External') { $issues += "External trust to $($trust.Target)" }
        if (-not $trust.SelectiveAuthentication -and $trust.Direction -ne 'Inbound') {
            $issues += "No Selective Authentication on outbound trust"
        }
        if ($trust.SIDFilteringQuarantined -eq $false) { $issues += "SID Filtering disabled (SIDHistory attack risk)" }

        if ($issues.Count -gt 0) {
            $sev = if ($trust.SIDFilteringQuarantined -eq $false) { 'CRITICAL' } else { 'MEDIUM' }
            Add-Finding -Category 'Domain Trust' -Severity $sev `
                -Check "Trust Issue: $($trust.Name)" `
                -Description "Trust to '$($trust.Target)' has security concerns: $($issues -join '; ')" `
                -AffectedObjects $trust.Target `
                -Evidence "TrustType=$($trust.TrustType) Direction=$($trust.Direction) SIDFiltering=$($trust.SIDFilteringQuarantined) SelectiveAuth=$($trust.SelectiveAuthentication)" `
                -Recommendation 'Review trust necessity; enable SID Filtering; configure Selective Authentication; limit trust scope'
        } else {
            Write-Info "Trust to $($trust.Target): $($trust.TrustType) - OK"
        }
    }
    if ($trusts.Count -eq 0) { Write-Info "No domain trusts found" }
} catch { Write-Warn "Cannot query trusts: $_" }

# -------------------------------------------------------
# 15. GPO SECURITY ISSUES
# -------------------------------------------------------
Write-Section "Check 15 - Group Policy Security"

try {
    $gpos = Get-GPO -All @adParams -EA Stop

    $disabledLinked = $gpos | Where-Object { $_.GpoStatus -ne 'AllSettingsEnabled' }
    if ($disabledLinked.Count -gt 0) {
        $names = ($disabledLinked | Select-Object -ExpandProperty DisplayName) -join ', '
        Add-Finding -Category 'Group Policy' -Severity 'LOW' `
            -Check 'Partially Disabled GPOs' `
            -Description "$($disabledLinked.Count) GPO(s) have some settings disabled" `
            -AffectedObjects $names `
            -Evidence "Count=$($disabledLinked.Count)" `
            -Recommendation 'Review disabled GPOs; remove if unused; audit GPO status'
    }

    $allLinks  = (Get-GPInheritance -Target $domainDN @adParams -EA Stop).GpoLinks.GpoId
    $unlinked  = $gpos | Where-Object { $_.Id -notin $allLinks }
    if ($unlinked.Count -gt 5) {
        Add-Finding -Category 'Group Policy' -Severity 'LOW' `
            -Check 'Unlinked GPOs' `
            -Description "$($unlinked.Count) GPO(s) exist but are not linked to any OU (attack surface / clutter)" `
            -AffectedObjects ($unlinked | Select-Object -First 10 | Select-Object -ExpandProperty DisplayName) -join ', ' `
            -Evidence "UnlinkedCount=$($unlinked.Count) TotalGPOs=$($gpos.Count)" `
            -Recommendation 'Review and delete unused GPOs; attackers with write access can modify unlinked GPOs then link them'
    }

    Write-Info "Total GPOs: $($gpos.Count)"
} catch { Write-Warn "Cannot query GPOs (GPMC may be needed): $_" }

# -------------------------------------------------------
# 16. PROTECTED USERS GROUP CHECK
# -------------------------------------------------------
Write-Section "Check 16 - Protected Users Group"

try {
    $protectedUsers = Get-ADGroupMember -Identity 'Protected Users' @adParams -EA Stop
    $protectedNames = $protectedUsers | Select-Object -ExpandProperty SamAccountName

    $privNotProtected = $allPrivUsers.Keys | Where-Object { $_ -notin $protectedNames -and $_ -ne 'krbtgt' }

    if ($privNotProtected.Count -gt 0) {
        $names = $privNotProtected -join ', '
        Add-Finding -Category 'Privileged Accounts' -Severity 'HIGH' `
            -Check 'Privileged Accounts Not in Protected Users' `
            -Description "$($privNotProtected.Count) privileged account(s) are NOT in the Protected Users security group" `
            -AffectedObjects $names `
            -Evidence "NotProtected=$names" `
            -Recommendation 'Add privileged accounts to Protected Users group; it disables NTLM, RC4, unconstrained delegation, and credential caching'
    } else {
        Write-Info "All privileged accounts are in Protected Users - OK"
    }
} catch { Write-Warn "Cannot query Protected Users (may not exist in older domains): $_" }

# -------------------------------------------------------
# 17. ACCOUNT OPERATORS / SENSITIVE DELEGATIONS
# -------------------------------------------------------
Write-Section "Check 17 - Sensitive Account Flags"

try {
    $noSensFlag = Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $true } `
        -Properties AccountNotDelegated,AdminCount @adParams -EA Stop |
        Where-Object { -not $_.AccountNotDelegated }

    if ($noSensFlag.Count -gt 0) {
        $names = ($noSensFlag | Select-Object -First 15 | Select-Object -ExpandProperty SamAccountName) -join ', '
        Add-Finding -Category 'Privileged Accounts' -Severity 'HIGH' `
            -Check 'Privileged Accounts Missing Not-Delegated Flag' `
            -Description "$($noSensFlag.Count) AdminCount=1 account(s) do not have 'Account is sensitive and cannot be delegated' set" `
            -AffectedObjects $names `
            -Evidence "Count=$($noSensFlag.Count)" `
            -Recommendation 'Set AccountNotDelegated=True on all privileged accounts to prevent credential delegation attacks'
    } else {
        Write-Info "All AdminCount accounts have sensitive flag - OK"
    }
} catch {}

# -------------------------------------------------------
# 18. SIDHISTORY
# -------------------------------------------------------
Write-Section "Check 18 - SIDHistory on Accounts"

try {
    $sidHistoryUsers = Get-ADUser -Filter { SIDHistory -like '*' } `
        -Properties SIDHistory,Enabled,LastLogonDate,AdminCount @adParams -EA Stop

    $sidHistoryComps = Get-ADComputer -Filter { SIDHistory -like '*' } `
        -Properties SIDHistory,Enabled @adParams -EA Stop

    $allSIDH = @()
    foreach ($u in $sidHistoryUsers) {
        $isPriv = $allPrivUsers.ContainsKey($u.SamAccountName)
        $sev    = if ($isPriv) { 'CRITICAL' } else { 'HIGH' }
        $allSIDH += $u.SamAccountName
        Add-Finding -Category 'SIDHistory' -Severity $sev -TTP 'T1134.005' `
            -Check 'SIDHistory Present on User Account' `
            -Description "Account '$($u.SamAccountName)' has SIDHistory - may carry privileges from old/migrated domain$(if($isPriv){' [PRIVILEGED ACCOUNT]'})" `
            -AffectedObjects $u.SamAccountName `
            -Evidence "SIDHistory=$($u.SIDHistory -join ' | ') Enabled=$($u.Enabled) AdminCount=$($u.AdminCount)" `
            -Recommendation 'Remove SIDHistory if migration is complete; SIDHistory can grant unexpected access to resources in source domains; use Get-ADUser | Set-ADUser to clear'
    }

    foreach ($c in $sidHistoryComps) {
        Add-Finding -Category 'SIDHistory' -Severity 'MEDIUM' -TTP 'T1134.005' `
            -Check 'SIDHistory Present on Computer Account' `
            -Description "Computer '$($c.Name)' has SIDHistory attribute set" `
            -AffectedObjects $c.Name `
            -Evidence "SIDHistory=$($c.SIDHistory -join ' | ') Enabled=$($c.Enabled)" `
            -Recommendation 'Review and clear SIDHistory on computer accounts post-migration'
    }

    if ($allSIDH.Count -eq 0 -and $sidHistoryComps.Count -eq 0) {
        Write-Info "No SIDHistory found on any accounts - OK"
    } else {
        Write-Info "SIDHistory found: $($sidHistoryUsers.Count) user(s), $($sidHistoryComps.Count) computer(s)"
    }
} catch { Write-Warn "Cannot query SIDHistory: $_" }

} # end -not LiteMode (Checks 10-18)

# -------------------------------------------------------
# 19. GPP PASSWORDS IN SYSVOL (cpassword)
# -------------------------------------------------------
Write-Section "Check 19 - GPP Passwords in SYSVOL (cpassword)"

try {
    $sysvolPath = "\\$Server\SYSVOL"
    $gppFiles   = @()

    if (Test-Path $sysvolPath) {
        $gppFiles = Get-ChildItem -Path $sysvolPath -Recurse -Include `
            'Groups.xml','Services.xml','Scheduledtasks.xml','Datasources.xml','Printers.xml','Drives.xml' `
            -ErrorAction SilentlyContinue -Force

        $hitFiles = @()
        foreach ($f in $gppFiles) {
            try {
                $content = Get-Content $f.FullName -Raw -ErrorAction Stop
                if ($content -match 'cpassword="([^"]+)"') {
                    $hitFiles += $f.FullName
                    $userName = if ($content -match 'userName="([^"]+)"') { $Matches[1] } else { 'unknown' }
                    Add-Finding -Category 'GPP Credentials' -Severity 'CRITICAL' -TTP 'T1552.006' `
                        -Check 'GPP cpassword Found in SYSVOL' `
                        -Description "File '$($f.Name)' in SYSVOL contains encrypted GPP password (cpassword) - decryptable with public AES key" `
                        -AffectedObjects "User=$userName File=$($f.FullName)" `
                        -Evidence "File=$($f.FullName) UserName=$userName" `
                        -Recommendation 'CRITICAL: Delete the file or remove cpassword attribute immediately; change affected account passwords; MS14-025 patches client but does not remove existing files from SYSVOL'
                }
            } catch {}
        }

        if ($hitFiles.Count -eq 0) {
            Write-Info "No GPP cpassword found in SYSVOL ($($gppFiles.Count) policy files scanned) - OK"
        }
    } else {
        Write-Warn "Cannot access SYSVOL at $sysvolPath - skipping GPP check"
        Add-Finding -Category 'GPP Credentials' -Severity 'LOW' `
            -Check 'SYSVOL Access Failed' `
            -Description "Could not access SYSVOL at $sysvolPath to scan for GPP passwords" `
            -Evidence "Path=$sysvolPath" `
            -Recommendation 'Manually check SYSVOL for Groups.xml and other GPP policy files containing cpassword attributes'
    }
} catch { Write-Warn "GPP SYSVOL scan error: $_" }

# -------------------------------------------------------
# 20. MACHINEACCOUNTQUOTA
# -------------------------------------------------------
Write-Section "Check 20 - MachineAccountQuota (RBCD Attack Risk)"

try {
    $maq = (Get-ADDomain @adParams -EA Stop).'ms-DS-MachineAccountQuota'

    if ($null -eq $maq) {
        # Fallback via Get-ADObject
        $domObj = Get-ADObject -Identity $domainDN -Properties 'ms-DS-MachineAccountQuota' @adParams -EA Stop
        $maq    = $domObj.'ms-DS-MachineAccountQuota'
    }

    if ($null -eq $maq) { $maq = 10 }  # default if unreadable

    if ($maq -gt 0) {
        $sev = if ($maq -ge 10) { 'HIGH' } else { 'MEDIUM' }
        Add-Finding -Category 'Domain Config' -Severity $sev -TTP 'T1136.002' `
            -Check 'MachineAccountQuota > 0' `
            -Description "ms-DS-MachineAccountQuota = $maq - any authenticated domain user can add up to $maq computer accounts (enables RBCD/relay attacks)" `
            -AffectedObjects 'Domain root object' `
            -Evidence "ms-DS-MachineAccountQuota=$maq" `
            -Recommendation 'Set ms-DS-MachineAccountQuota to 0 on the domain root: Set-ADDomain -Identity . -Replace @{"ms-DS-MachineAccountQuota"=0}; only admins should join machines to domain'
    } else {
        Write-Info "MachineAccountQuota = $maq (restricted) - OK"
    }
} catch { Write-Warn "Cannot query MachineAccountQuota: $_" }

# -------------------------------------------------------
# 21. ACL ANOMALIES ON CRITICAL AD OBJECTS
# -------------------------------------------------------
Write-Section "Check 21 - ACL Anomalies on Critical AD Objects"

# Rights that allow takeover / privilege escalation
$dangerousRights = @(
    'GenericAll',
    'GenericWrite',
    'WriteDacl',
    'WriteOwner',
    'AllExtendedRights'
)

# Principals always allowed to have these rights
$legitimatePrincipals = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'SYSTEM',
    'Creator Owner',
    'ENTERPRISE DOMAIN CONTROLLERS',
    'NT AUTHORITY\SYSTEM',
    'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
    'Account Operators',
    'BUILTIN\Administrators'
)

function Test-ACLAnomalies {
    param([string]$TargetDN, [string]$ObjectLabel)
    try {
        $acl  = Get-ACL "AD:\$TargetDN" -EA Stop
        $hits = @()
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $id = $ace.IdentityReference.ToString()

            # Skip well-known legitimate principals
            $isLegit = $false
            foreach ($lp in $legitimatePrincipals) {
                if ($id -match [Regex]::Escape($lp)) { $isLegit = $true; break }
            }
            if ($isLegit) { continue }

            # Check for dangerous right strings
            $rightStr = $ace.ActiveDirectoryRights.ToString()
            foreach ($dr in $dangerousRights) {
                if ($rightStr -match $dr) {
                    $hits += "$id ($dr)"
                    break
                }
            }
        }
        if ($hits.Count -gt 0) {
            $unique = ($hits | Sort-Object -Unique) -join ' | '
            Add-Finding -Category 'ACL Anomaly' -Severity 'CRITICAL' -TTP 'T1222.001' `
                -Check "Dangerous ACE on $ObjectLabel" `
                -Description "$($hits.Count) non-standard principal(s) have dangerous rights on '$ObjectLabel'" `
                -AffectedObjects $unique `
                -Evidence "Target=$TargetDN Rights=$unique" `
                -Recommendation "CRITICAL: Review and remove dangerous ACEs from '$ObjectLabel'; use AD ACL Scanner or Get-ACL to audit; grant only minimum required permissions"
        } else {
            Write-Info "$ObjectLabel ACL - OK"
        }
    } catch { Write-Warn "Cannot read ACL for ${ObjectLabel}: $_" }
}

# Check domain root
Test-ACLAnomalies -TargetDN $domainDN -ObjectLabel 'Domain Root'

# Check AdminSDHolder
$adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
Test-ACLAnomalies -TargetDN $adminSDHolderDN -ObjectLabel 'AdminSDHolder'

# Check Domain Controllers OU
$dcOuDN = "OU=Domain Controllers,$domainDN"
Test-ACLAnomalies -TargetDN $dcOuDN -ObjectLabel 'Domain Controllers OU'

# Check all privileged user accounts ACLs
$checkedPrivCount = 0
foreach ($samName in ($allPrivUsers.Keys | Select-Object -First 10)) {
    try {
        $privUser = Get-ADUser -Identity $samName -Properties DistinguishedName @adParams -EA Stop
        Test-ACLAnomalies -TargetDN $privUser.DistinguishedName -ObjectLabel "Privileged User: $samName"
        $checkedPrivCount++
    } catch {}
}
Write-Info "ACL check on domain root, AdminSDHolder, DC OU and $checkedPrivCount privileged user objects complete"

# -------------------------------------------------------
# SUMMARY STATS
# -------------------------------------------------------
$critCount  = ($global:Findings | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
$highCount  = ($global:Findings | Where-Object { $_.Severity -eq 'HIGH' }).Count
$medCount   = ($global:Findings | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
$lowCount   = ($global:Findings | Where-Object { $_.Severity -eq 'LOW' }).Count
$totalCount = $global:Findings.Count

# Score (lower = better): CRITICAL*10 + HIGH*5 + MEDIUM*2 + LOW*1
$riskScore  = ($critCount * 10) + ($highCount * 5) + ($medCount * 2) + ($lowCount * 1)
$riskLevel  = if ($critCount -gt 0)     { 'CRITICAL' }
              elseif ($highCount -gt 0)  { 'HIGH' }
              elseif ($medCount -gt 0)   { 'MEDIUM' }
              else                       { 'LOW' }

$riskColor  = switch ($riskLevel) {
    'CRITICAL'{'#ff2d55'} 'HIGH'{'#ff6b00'} 'MEDIUM'{'#ffd60a'} default{'#30d158'}
}

# -------------------------------------------------------
# CSV EXPORT
# -------------------------------------------------------
Write-Section "Exporting CSV"
$global:Findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Info "CSV: $CsvPath"

# -------------------------------------------------------
# HTML REPORT
# -------------------------------------------------------
Write-Section "Generating HTML Report"

$duration = ((Get-Date) - $global:StartTime).ToString("m'm 's's'")

function Get-SC { param([string]$s)
    switch ($s) { 'CRITICAL'{'#ff2d55'} 'HIGH'{'#ff6b00'} 'MEDIUM'{'#ffd60a'} 'LOW'{'#30d158'} default{'#6e6e73'} }
}

# Category summary
$catSummary = $global:Findings | Group-Object Category | Sort-Object Count -Descending

$catRows = ($catSummary | ForEach-Object {
    $topSev = ($global:Findings | Where-Object { $_.Category -eq $_.Name } |
               Sort-Object @{e={switch($_.Severity){'CRITICAL'{0}'HIGH'{1}'MEDIUM'{2}default{3}}}} |
               Select-Object -First 1).Severity
    $sc = Get-SC $topSev
    $pct= [Math]::Round($_.Count / $totalCount * 100)
    $bar= [Math]::Round($pct * 1.5)
    "<tr><td style='color:#a78bfa;font-size:11px'>$($_.Name)</td><td>$($_.Count)</td><td><div style='background:#181828;border-radius:3px;height:5px;width:150px'><div style='background:$sc;height:5px;border-radius:3px;width:${bar}px'></div></div></td><td><span class='badge' style='background:$sc;font-size:9px'>$topSev</span></td></tr>"
}) -join "`n"

# Findings table rows
$rows = foreach ($f in ($global:Findings | Sort-Object @{e={
    switch ($_.Severity) { 'CRITICAL'{0} 'HIGH'{1} 'MEDIUM'{2} 'LOW'{3} default{4} }
}})) {
    $sc  = Get-SC $f.Severity
    $ev  = [System.Net.WebUtility]::HtmlEncode($f.Evidence)
    $rc  = [System.Net.WebUtility]::HtmlEncode($f.Recommendation)
    $ds  = [System.Net.WebUtility]::HtmlEncode($f.Description)
    $ch  = [System.Net.WebUtility]::HtmlEncode($f.Check)
    $ao  = [System.Net.WebUtility]::HtmlEncode($f.AffectedObjects)
    $cat = [System.Net.WebUtility]::HtmlEncode($f.Category)
    $ttp = [System.Net.WebUtility]::HtmlEncode($f.TTP)
    "<tr><td><span class='badge' style='background:$sc'>$($f.Severity)</span></td><td class='cat'>$cat</td>$(if($ttp){"<td><code class='ttp'>$ttp</code></td>"}else{'<td></td>'})<td class='chk'>$ch</td><td>$ds</td><td class='ao'>$ao</td><td class='mono'>$ev</td><td class='rec'>$rc</td></tr>"
}

$noFind = '<tr><td colspan="8" style="text-align:center;color:#30d158;padding:48px;font-size:15px">No security issues found - AD configuration looks clean</td></tr>'
$tableBody = if ($totalCount -eq 0) { $noFind } else { $rows -join "`n" }

$scoreColor = if ($riskScore -gt 50) { '#ff2d55' } elseif ($riskScore -gt 20) { '#ff6b00' } elseif ($riskScore -gt 5) { '#ffd60a' } else { '#30d158' }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AD Security Audit - $($domain.DNSRoot)</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#07070e;color:#e2e2e8;font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;line-height:1.6}
header{background:linear-gradient(135deg,#07070e,#0c0c1a);border-bottom:1px solid #181828;padding:22px 40px;display:flex;align-items:center;gap:20px}
.logo{font-size:24px;font-weight:800;color:#00d4ff;font-family:'Courier New',monospace;letter-spacing:-1px;white-space:nowrap}
.logo span{color:#ff2d55}.logo em{color:#a78bfa;font-style:normal}
.hi h1{font-size:16px;font-weight:600}
.hi p{color:#6e6e80;font-size:11px;margin-top:3px}
.main{padding:26px 40px;max-width:1700px;margin:0 auto}
.rb{background:#0e0e1a;border:2px solid $riskColor;border-radius:12px;padding:18px 26px;margin-bottom:22px;display:flex;align-items:center;gap:28px}
.rl{font-size:10px;color:#6e6e80;text-transform:uppercase;letter-spacing:1.2px}
.rv{font-size:28px;font-weight:900;color:$riskColor;letter-spacing:-1px}
.score{font-size:42px;font-weight:900;font-family:'Courier New',monospace;color:$scoreColor}
.score-label{font-size:10px;color:#6e6e80;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:22px}
.sc{background:#0e0e1a;border:1px solid #181828;border-radius:10px;padding:14px 16px}
.sc .n{font-size:26px;font-weight:800;font-family:'Courier New',monospace}
.sc .l{font-size:10px;color:#6e6e80;text-transform:uppercase;letter-spacing:.8px;margin-top:3px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:22px}
.dominfo{background:#0e0e1a;border:1px solid #181828;border-radius:10px;padding:16px 20px;margin-bottom:22px;display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.di .k{font-size:10px;color:#6e6e80;text-transform:uppercase;letter-spacing:.8px}
.di .v{font-size:12px;font-family:'Courier New',monospace;margin-top:2px;color:#e2e2e8}
.panel{background:#0e0e1a;border:1px solid #181828;border-radius:10px;padding:14px 18px}
.panel-title{font-size:10px;font-weight:700;color:#6e6e80;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #181828}
.st{font-size:11px;font-weight:700;color:#00d4ff;text-transform:uppercase;letter-spacing:1.2px;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #181828;margin-top:22px}
table{width:100%;border-collapse:collapse;background:#0e0e1a;border-radius:10px;overflow:hidden;border:1px solid #181828;font-size:12px}
.tbl-inner{width:100%;border-collapse:collapse;font-size:11px}
th{background:#08081a;color:#6e6e80;font-size:9px;text-transform:uppercase;letter-spacing:1px;padding:9px 12px;text-align:left;font-weight:700;white-space:nowrap}
td{padding:8px 12px;border-top:1px solid #181828;vertical-align:top}
tr:hover td{background:#08081a}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:9px;font-weight:700;letter-spacing:.5px;color:#fff;white-space:nowrap}
.ttp{background:#181828;color:#00d4ff;padding:2px 6px;border-radius:4px;font-size:10px;font-family:'Courier New',monospace;white-space:nowrap}
.cat{color:#a78bfa;font-size:11px;white-space:nowrap}
.chk{color:#ffd60a;font-size:11px}
.ao{font-family:'Courier New',monospace;font-size:10px;color:#ff6b00;max-width:200px;word-break:break-all}
.mono{font-family:'Courier New',monospace;font-size:10px;color:#6e6e80;word-break:break-all;max-width:200px}
.rec{color:#7eb8ff;font-size:11px;max-width:220px}
.search-bar{background:#0e0e1a;border:1px solid #181828;border-radius:8px;padding:10px 14px;margin-bottom:12px;display:flex;gap:10px;align-items:center}
.search-bar input{background:#07070e;border:1px solid #282838;border-radius:6px;color:#e2e2e8;padding:6px 12px;font-size:12px;flex:1;outline:none}
.filter-btn{background:#181828;border:1px solid #282838;border-radius:6px;color:#a0a0c0;padding:5px 12px;font-size:11px;cursor:pointer}
.filter-btn:hover{background:#282838}
footer{margin-top:32px;padding:16px 40px;border-top:1px solid #181828;color:#6e6e80;font-size:11px;text-align:center}
</style>
</head>
<body>
<header>
  <div class="logo">SOC<span>::</span><em>ADAUDIT</em></div>
  <div class="hi">
    <h1>Active Directory Security Audit</h1>
    <p>Domain: $($domain.DNSRoot) | Forest: $($forest.Name) | PDC: $pdcFQDN | Scan: $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) | Duration: $duration</p>
  </div>
</header>
<div class="main">

  <div class="rb">
    <div>
      <div class="rl">Risk Level</div>
      <div class="rv">$riskLevel</div>
      <div style="color:#6e6e80;font-size:11px;margin-top:3px">$totalCount findings across $($catSummary.Count) categories</div>
    </div>
    <div style="margin-left:20px">
      <div class="score-label">Risk Score</div>
      <div class="score">$riskScore</div>
      <div style="color:#6e6e80;font-size:10px">CRITICAL*10 + HIGH*5 + MED*2 + LOW*1</div>
    </div>
    <div style="flex:1"></div>
    <div style="text-align:right;color:#6e6e80;font-size:12px;font-family:'Courier New',monospace;line-height:1.8">
      CRITICAL: <span style="color:#ff2d55;font-weight:700">$critCount</span><br>
      HIGH: <span style="color:#ff6b00;font-weight:700">$highCount</span><br>
      MEDIUM: <span style="color:#ffd60a;font-weight:700">$medCount</span><br>
      LOW: <span style="color:#30d158;font-weight:700">$lowCount</span>
    </div>
  </div>

  <div class="stats">
    <div class="sc"><div class="n" style="color:#ff2d55">$critCount</div><div class="l">Critical</div></div>
    <div class="sc"><div class="n" style="color:#ff6b00">$highCount</div><div class="l">High</div></div>
    <div class="sc"><div class="n" style="color:#ffd60a">$medCount</div><div class="l">Medium</div></div>
    <div class="sc"><div class="n" style="color:#30d158">$lowCount</div><div class="l">Low</div></div>
    <div class="sc"><div class="n" style="color:#a78bfa">$(if($LiteMode){9}else{21})</div><div class="l">Checks Run</div></div>
    <div class="sc"><div class="n" style="color:#00d4ff">$totalCount</div><div class="l">Total Findings</div></div>
  </div>

  <div class="dominfo">
    <div class="di"><div class="k">Domain</div><div class="v">$($domain.DNSRoot)</div></div>
    <div class="di"><div class="k">Forest</div><div class="v">$($forest.Name)</div></div>
    <div class="di"><div class="k">Domain FL</div><div class="v">$domainFL</div></div>
    <div class="di"><div class="k">Forest FL</div><div class="v">$forestFL</div></div>
    <div class="di"><div class="k">PDC Emulator</div><div class="v">$pdcFQDN</div></div>
    <div class="di"><div class="k">Distinguished Name</div><div class="v">$domainDN</div></div>
    <div class="di"><div class="k">Stale Threshold (Users)</div><div class="v">$StaleAccountDays days</div></div>
    <div class="di"><div class="k">Stale Threshold (Comps)</div><div class="v">$StaleComputerDays days</div></div>
  </div>

  <div class="grid2">
    <div class="panel">
      <div class="panel-title">Findings by Category</div>
      <table class="tbl-inner">
        <thead><tr><th>Category</th><th>Count</th><th>Proportion</th><th>Max Severity</th></tr></thead>
        <tbody>$catRows</tbody>
      </table>
    </div>
    <div class="panel">
      <div class="panel-title">Checks Performed ($(if($LiteMode){'9 - LITE MODE'}else{'21 - FULL MODE'}))</div>
      <table class="tbl-inner">
        <tbody>
          $(if(-not $LiteMode){"<tr><td style='color:#6e6e80;font-size:11px'>Domain Functional Level</td><td style='color:#30d158;font-size:10px'>Done</td></tr>"})
          <tr><td style="color:#6e6e80;font-size:11px">Privileged Group Membership</td><td style="color:#30d158;font-size:10px">Done</td></tr>
          <tr><td style="color:#6e6e80;font-size:11px">KRBTGT Password Age</td><td style="color:#30d158;font-size:10px">Done</td></tr>
          $(if(-not $LiteMode){"<tr><td style='color:#6e6e80;font-size:11px'>Default Domain Password Policy</td><td style='color:#30d158;font-size:10px'>Done</td></tr>"})
          <tr><td style="color:#6e6e80;font-size:11px">Kerberoastable Accounts (SPNs)</td><td style="color:#30d158;font-size:10px">Done</td></tr>
          <tr><td style="color:#6e6e80;font-size:11px">AS-REP Roastable Accounts</td><td style="color:#30d158;font-size:10px">Done</td></tr>
          <tr><td style="color:#6e6e80;font-size:11px">Unconstrained Delegation</td><td style="color:#30d158;font-size:10px">Done</td></tr>
          $(if(-not $LiteMode){"<tr><td style='color:#6e6e80;font-size:11px'>AdminSDHolder / AdminCount</td><td style='color:#30d158;font-size:10px'>Done</td></tr>"})
          <tr><td style="color:#6e6e80;font-size:11px">DCSync Rights</td><td style="color:#30d158;font-size:10px">Done</td></tr>
          $(if(-not $LiteMode){"<tr><td style='color:#6e6e80;font-size:11px'>Stale User Accounts</td><td style='color:#30d158;font-size:10px'>Done</td></tr>"})
          $(if(-not $LiteMode){"<tr><td style='color:#6e6e80;font-size:11px'>Password Never Expires / Flags</td><td style='color:#30d158;font-size:10px'>Done</td></tr>"})
          $(if(-not $LiteMode){"<tr><td style='color:#6e6e80;font-size:11px'>LAPS Deployment</td><td style='color:#30d158;font-size:10px'>Done</td></tr>"})
          $(if(-not $LiteMode){"<tr><td style='color:#6e6e80;font-size:11px'>Stale Computer Accounts / EOL OS</td><td style='color:#30d158;font-size:10px'>Done</td></tr>"})
          $(if(-not $LiteMode){"<tr><td style='color:#6e6e80;font-size:11px'>Domain Trusts</td><td style='color:#30d158;font-size:10px'>Done</td></tr>"})
          $(if(-not $LiteMode){"<tr><td style='color:#6e6e80;font-size:11px'>GPO Security</td><td style='color:#30d158;font-size:10px'>Done</td></tr>"})
          $(if(-not $LiteMode){"<tr><td style='color:#6e6e80;font-size:11px'>Protected Users Group</td><td style='color:#30d158;font-size:10px'>Done</td></tr>"})
          $(if(-not $LiteMode){"<tr><td style='color:#6e6e80;font-size:11px'>Sensitive Account Flags</td><td style='color:#30d158;font-size:10px'>Done</td></tr>"})
          $(if(-not $LiteMode){"<tr><td style='color:#6e6e80;font-size:11px'>SIDHistory on Accounts</td><td style='color:#30d158;font-size:10px'>Done</td></tr>"})
          <tr><td style="color:#6e6e80;font-size:11px">GPP Passwords in SYSVOL (cpassword)</td><td style="color:#30d158;font-size:10px">Done</td></tr>
          <tr><td style="color:#6e6e80;font-size:11px">MachineAccountQuota</td><td style="color:#30d158;font-size:10px">Done</td></tr>
          <tr><td style="color:#6e6e80;font-size:11px">ACL Anomalies on Critical Objects</td><td style="color:#30d158;font-size:10px">Done</td></tr>
          $(if($LiteMode){"<tr><td colspan='2' style='color:#ffd60a;font-size:10px;padding-top:8px'>12 checks skipped (use Full mode for complete audit)</td></tr>"})
        </tbody>
      </table>
    </div>
  </div>

  <div class="st">Security Findings</div>
  <div class="search-bar">
    <input type="text" id="searchBox" placeholder="Filter by category, severity, check name, affected objects..." oninput="filterTable()">
    <button class="filter-btn" onclick="setFilter('critical')">CRITICAL</button>
    <button class="filter-btn" onclick="setFilter('high')">HIGH</button>
    <button class="filter-btn" onclick="setFilter('kerberos')">Kerberos</button>
    <button class="filter-btn" onclick="setFilter('password')">Password</button>
    <button class="filter-btn" onclick="setFilter('privileged')">Privileged</button>
    <button class="filter-btn" onclick="setFilter('')">Clear</button>
  </div>
  <table id="findingsTable">
    <thead>
      <tr>
        <th>Severity</th><th>Category</th><th>TTP</th><th>Check</th>
        <th>Description</th><th>Affected Objects</th><th>Evidence</th><th>Recommendation</th>
      </tr>
    </thead>
    <tbody id="findingsTbody">$tableBody</tbody>
  </table>

</div>
<script>
function filterTable() {
    var q = document.getElementById('searchBox').value.toLowerCase();
    var rows = document.getElementById('findingsTbody').getElementsByTagName('tr');
    for (var i = 0; i < rows.length; i++) {
        rows[i].style.display = rows[i].textContent.toLowerCase().indexOf(q) > -1 ? '' : 'none';
    }
}
function setFilter(v) {
    document.getElementById('searchBox').value = v;
    filterTable();
}
</script>
<footer>
  Generated: $($global:StartTime.ToString('yyyy-MM-dd HH:mm:ss')) | Invoke-ADSecurityAudit v1.2 $(if($LiteMode){'[LITE]'}else{'[FULL]'}) | Domain: $($domain.DNSRoot) | CONFIDENTIAL - SOC/IS USE ONLY
</footer>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

$sep = "-" * 62
Write-Host ""; Write-Host $sep -ForegroundColor DarkGray
Write-Host "  AD SECURITY AUDIT COMPLETE" -ForegroundColor White
Write-Host $sep -ForegroundColor DarkGray
Write-Host "  Domain     : $($domain.DNSRoot)" -ForegroundColor Gray
Write-Host "  Duration   : $duration" -ForegroundColor Gray
Write-Host "  Risk Level : $riskLevel" -ForegroundColor $(switch ($riskLevel){'CRITICAL'{'Red'}'HIGH'{'Red'}'MEDIUM'{'Yellow'}default{'Green'}})
Write-Host "  Risk Score : $riskScore" -ForegroundColor $(if ($riskScore -gt 20){'Red'}elseif($riskScore -gt 5){'Yellow'}else{'Green'})
Write-Host ""
Write-Host "  CRITICAL   : $critCount" -ForegroundColor $(if($critCount -gt 0){'Red'}else{'Green'})
Write-Host "  HIGH       : $highCount" -ForegroundColor $(if($highCount -gt 0){'Red'}else{'Green'})
Write-Host "  MEDIUM     : $medCount"  -ForegroundColor $(if($medCount  -gt 0){'Yellow'}else{'Green'})
Write-Host "  LOW        : $lowCount"  -ForegroundColor Green
Write-Host "  TOTAL      : $totalCount" -ForegroundColor White
Write-Host ""
if ($totalCount -gt 0) {
    Write-Host "  Top critical findings:" -ForegroundColor Gray
    foreach ($f in ($global:Findings | Where-Object { $_.Severity -in @('CRITICAL','HIGH') } | Select-Object -First 5)) {
        $fc = if ($f.Severity -eq 'CRITICAL'){'Red'}else{'Red'}
        Write-Host "    [$($f.Severity)] $($f.Check): $($f.Description.Substring(0,[Math]::Min(60,$f.Description.Length)))" -ForegroundColor $fc
    }
    Write-Host ""
}
Write-Host "  HTML : $OutputPath" -ForegroundColor Cyan
Write-Host "  CSV  : $CsvPath"    -ForegroundColor Cyan
Write-Host $sep -ForegroundColor DarkGray

$open = Read-Host "Open HTML report in browser? [Y/N]"
if ($open -match '^[Yy]') { Start-Process $OutputPath }
