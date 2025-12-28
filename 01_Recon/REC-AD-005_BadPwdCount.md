# REC-AD-005: BadPwdCount Attribute Monitoring

**SERVTEP ID:** REC-AD-005  
**Technique Name:** BadPwdCount attribute monitoring  
**MITRE ATT&CK Mapping:** T1087.002 (Account Discovery - Domain Account)  
**CVE Reference:** N/A  
**Environment:** Windows Active Directory  
**Severity:** Medium  
**Difficulty:** Medium  

---

## Executive Summary

The `badPwdCount` attribute in Active Directory tracks the number of failed login attempts for a user account. Attackers monitor this attribute to identify accounts that have been recently targeted for password guessing or brute-force attacks. Additionally, adversaries can weaponize knowledge of this attribute to identify accounts with weak password policies, accounts under active attack, or to determine when their own compromise attempts have failed. This reconnaissance technique provides insight into both the security posture and active threat activity within a domain.

---

## Objective

Monitor and analyze badPwdCount attribute to:
- Identify accounts under active password attack
- Detect locked-out accounts (recent failed logins)
- Find accounts with weak password security
- Determine effective password complexity enforcement
- Identify service accounts being targeted
- Reveal patterns of credential compromise attempts
- Assess domain password policy effectiveness
- Prioritize accounts for targeted attack

---

## Prerequisites

- Network connectivity to Active Directory domain controller
- LDAP query capability (port 389)
- Directory querying tools (ldapsearch, PowerShell, AdFind)
- Active Directory user credentials (optional for some queries)
- Understanding of domain password lockout policy

---

## Execution Procedures

### Method 1: Query BadPwdCount via LDAP

**Step 1:** Enumerate all accounts with failed login attempts
```bash
# Query all users with badPwdCount > 0
ldapsearch -h <dc-ip> -p 389 -x -b "DC=example,DC=com" \
  "badPwdCount=*" sAMAccountName badPwdCount mail

# Filter for accounts with recent failed attempts (last hour)
ldapsearch -h <dc-ip> -p 389 -x -b "DC=example,DC=com" \
  "(&(badPwdCount>=1)(badPwdCount<=10))" \
  sAMAccountName badPwdCount lastLogonTimestamp

# Get accounts with high failed attempt counts
ldapsearch -h <dc-ip> -p 389 -x -b "DC=example,DC=com" \
  "(badPwdCount>=5)" sAMAccountName badPwdCount pwdLastSet
```

**Step 2:** Export badPwdCount data for analysis
```bash
# Export all users with their badPwdCount
ldapsearch -h <dc-ip> -p 389 -x -b "DC=example,DC=com" \
  "(objectClass=user)" sAMAccountName badPwdCount mail > badpwdcount_dump.ldif

# Parse and extract
grep -E "^(sAMAccountName|badPwdCount|mail):" badpwdcount_dump.ldif > badpwdcount_parsed.txt
```

### Method 2: PowerShell Enumeration

**Step 1:** Query badPwdCount using PowerView
```powershell
# Get all users with badPwdCount attribute
Get-NetUser | Select-Object samAccountName, badPwdCount, mail | 
  Where-Object {$_.badPwdCount -gt 0}

# Find accounts with high failed attempt counts
Get-NetUser | 
  Where-Object {$_.badPwdCount -ge 5} |
  Select-Object samAccountName, badPwdCount, pwdLastSet, lastLogonTimestamp

# Export accounts under attack
$underAttack = Get-NetUser | Where-Object {$_.badPwdCount -ge 3}
$underAttack | Export-Csv accounts_under_attack.csv -NoTypeInformation
```

**Step 2:** Correlate badPwdCount with password policy
```powershell
# Get domain password policy
$policy = Get-DomainPolicyData

$maxFailed = $policy.SystemAccess.LockoutBadCount
$duration = $policy.SystemAccess.LockoutDuration

Write-Host "Max Failed Attempts Before Lockout: $maxFailed"
Write-Host "Lockout Duration (minutes): $duration"

# Find accounts approaching lockout threshold
$threshold = $maxFailed - 2

Get-NetUser | 
  Where-Object {$_.badPwdCount -ge $threshold} |
  Select-Object samAccountName, badPwdCount
```

**Step 3:** Identify service accounts under attack
```powershell
# Find service accounts with elevated badPwdCount
Get-NetUser | 
  Where-Object {$_.samAccountName -like "*svc*" -and $_.badPwdCount -gt 0} |
  Select-Object samAccountName, badPwdCount, description

# Identify admin accounts being targeted
Get-NetGroupMember -GroupName "Domain Admins" |
  ForEach-Object {Get-NetUser -Username $_.memberName} |
  Where-Object {$_.badPwdCount -gt 0} |
  Select-Object samAccountName, badPwdCount
```

### Method 3: ADSI-Based Enumeration

**Step 1:** Direct ADSI queries for badPwdCount
```powershell
# Connect to Active Directory
$domain = "DC=example,DC=com"
$de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domain")

# Create searcher
$searcher = New-Object System.DirectoryServices.DirectorySearcher($de)

# Find all users with failed attempts
$searcher.Filter = "(&(objectClass=user)(badPwdCount>=1))"
$searcher.PropertiesToLoad.AddRange(@("sAMAccountName", "badPwdCount", "mail"))

$results = $searcher.FindAll()

foreach ($result in $results) {
  $user = $result.Properties
  Write-Host "User: $($user['sAMAccountName'][0])"
  Write-Host "Failed Attempts: $($user['badPwdCount'][0])"
  Write-Host "Email: $($user['mail'][0])"
  Write-Host "---"
}
```

**Step 2:** Monitor badPwdCount changes over time
```powershell
# Take baseline snapshot
$baseline = Get-NetUser | 
  Select-Object samAccountName, badPwdCount

# Wait for interval (e.g., 1 hour)
Start-Sleep -Seconds 3600

# Compare with current state
$current = Get-NetUser | 
  Select-Object samAccountName, badPwdCount

# Find increased badPwdCount
$comparison = Compare-Object $baseline $current -Property samAccountName, badPwdCount

$increased = $comparison | 
  Where-Object {$_.SideIndicator -eq "=>" -and $_.badPwdCount -gt 3}

if ($increased) {
  Write-Host "Accounts with increased failed attempts:"
  $increased | ForEach-Object {Write-Host "  - $($_.samAccountName): $($_.badPwdCount)"}
}
```

### Method 4: Automated Monitoring and Alerting

**Step 1:** Create continuous monitoring script
```powershell
# Monitor and log badPwdCount changes
$logFile = "C:\Logs\badpwdcount_monitor.log"

while ($true) {
  $timestamp = Get-Date
  
  # Get all users with badPwdCount > 0
  $problematicAccounts = Get-NetUser | 
    Where-Object {$_.badPwdCount -gt 0} |
    Select-Object samAccountName, badPwdCount, mail
  
  if ($problematicAccounts) {
    "$timestamp - Accounts with failed attempts:" | Add-Content $logFile
    $problematicAccounts | ConvertTo-Json | Add-Content $logFile
    
    # Alert if high attempt count
    $highRisk = $problematicAccounts | Where-Object {$_.badPwdCount -ge 8}
    if ($highRisk) {
      Write-Host "[ALERT] High-risk accounts detected!" -ForegroundColor Red
      $highRisk | ForEach-Object {
        Write-Host "  - $($_.samAccountName): $($_.badPwdCount) failed attempts"
      }
    }
  }
  
  # Wait before next check
  Start-Sleep -Seconds 300
}
```

**Step 2:** Export and analyze trends
```powershell
# Collect badPwdCount data for trend analysis
$data = @()

for ($i = 0; $i -lt 24; $i++) {
  $users = Get-NetUser | Where-Object {$_.badPwdCount -gt 0}
  
  foreach ($user in $users) {
    $data += [PSCustomObject]@{
      Timestamp = Get-Date
      User = $user.samAccountName
      FailedAttempts = $user.badPwdCount
      Hour = $i
    }
  }
  
  Start-Sleep -Seconds 3600
}

# Export for analysis
$data | Export-Csv badpwdcount_24hour.csv -NoTypeInformation

# Identify most-targeted accounts
$data | Group-Object User | 
  Select-Object Name, @{N="AvgFailures";E={($_.Group.FailedAttempts | Measure-Object -Average).Average}} |
  Sort-Object AvgFailures -Descending
```

### Method 5: Correlation with Attack Patterns

**Step 1:** Identify brute-force attack targets
```powershell
# Find accounts targeted by brute-force (high badPwdCount, recent)
$threshold = 5
$recentCutoff = (Get-Date).AddHours(-1)

Get-NetUser | 
  Where-Object {$_.badPwdCount -ge $threshold} |
  Where-Object {$_.lastLogonTimestamp -gt $recentCutoff} |
  Select-Object samAccountName, badPwdCount, lastLogonTimestamp, description
```

**Step 2:** Identify weak password targets
```powershell
# Accounts with old passwords and high badPwdCount (weak passwords)
$oldPasswordCutoff = (Get-Date).AddDays(-365)

Get-NetUser |
  Where-Object {$_.pwdLastSet -lt $oldPasswordCutoff} |
  Where-Object {$_.badPwdCount -gt 0} |
  Select-Object samAccountName, badPwdCount, pwdLastSet, description
```

**Step 3:** Map attack timeline
```powershell
# Get accounts with recent badPwdCount increases
$attackedAccounts = Get-NetUser | 
  Where-Object {$_.badPwdCount -ge 5}

$attackedAccounts | ForEach-Object {
  Write-Host "Target: $($_.samAccountName)"
  Write-Host "  Failed Attempts: $($_.badPwdCount)"
  Write-Host "  Last Logon: $($_.lastLogonTimestamp)"
  Write-Host "  Last Password Change: $($_.pwdLastSet)"
  Write-Host "  Enabled: $(if ($_.userAccountControl -band 2) {'No'} else {'Yes'})"
  Write-Host "---"
}
```

---

## Technical Deep Dive

### BadPwdCount Attribute Details

**Attribute Properties:**
- **Name:** badPwdCount
- **LDAP Display Name:** badPwdCount
- **Type:** Integer
- **Searchable:** Yes
- **Range:** 0-2147483647
- **Reset:** Automatic after lockout duration expires

**When badPwdCount Increments:**
1. Failed Kerberos pre-authentication (AS-REQ)
2. Failed NTLM authentication
3. Failed LDAP bind (simple authentication)
4. Failed RPC authentication

**When badPwdCount Resets:**
- Account is locked out (time-based reset)
- Successful authentication
- Manual reset by administrator

### Password Lockout Policy Interaction

| Policy Setting | Impact | Detection |
|---|---|---|
| LockoutBadCount | Max failed attempts before lockout | badPwdCount threshold |
| LockoutDuration | Time account stays locked | Correlate with login attempts |
| LockoutObservationWindow | Time window for failed attempts | Frequency of badPwdCount changes |

---

## Detection Strategies (Blue Team)

### BadPwdCount Monitoring

1. **Event Logging**
   - Event ID 4625: Failed login attempt
   - Event ID 4740: Account locked out
   - Event ID 4771: Kerberos pre-authentication failed

2. **Alert Triggers**
   - badPwdCount approaching lockout threshold
   - Service account with elevated badPwdCount
   - Multiple accounts with high badPwdCount (spray attack)
   - badPwdCount increases for admin accounts

3. **SIEM Rules**
   ```
   Alert Condition:
   - Multiple Event ID 4625 from single source IP
   - Multiple Event ID 4625 for different accounts from same IP
   - Service account lockouts (Event ID 4740)
   - badPwdCount > 5 for critical accounts
   ```

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Reconnaissance Value**
   - Identify accounts under active attack
   - Find weakly-enforced password policies
   - Discover service accounts (likely weak passwords)
   - Determine effective lockout thresholds

2. **Timing Awareness**
   - Monitor badPwdCount trends to avoid lockout
   - Adjust attack pace based on badPwdCount reset patterns
   - Coordinate multi-account attacks to distribute load

### Defensive Measures

1. **Attribute Protection**
   - Limit who can view badPwdCount attribute
   - Restrict LDAP query access
   - Monitor badPwdCount attribute access in logs

2. **Proactive Hardening**
   - Enforce strong password policies
   - Rotate service account passwords regularly
   - Use managed service accounts (gMSA) instead of static passwords
   - Implement account lockout notifications

---

## Mitigation Strategies

1. **Immediate Actions**
   - Review accounts with high badPwdCount
   - Force password resets for targeted accounts
   - Implement smart card or MFA for critical accounts

2. **Detection & Response**
   - Monitor Event ID 4625 and 4740
   - Alert on service account lockouts
   - Track badPwdCount trends

3. **Long-term Security**
   - Implement Managed Service Accounts (MSA)
   - Use passwordless authentication (Windows Hello, FIDO2)
   - Regular password policy reviews
   - Account lockout monitoring automation

---

## References & Further Reading

- [Active Directory: badPwdCount Attribute](https://docs.microsoft.com/en-us/windows/win32/adschema/a-badpwdcount)
- [Event ID 4625 - Failed Logon](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Account Lockout Policy](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)
- [Password Policy Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)

---

## Related SERVTEP Techniques

- **REC-AD-001**: Tenant Discovery (prerequisite)
- **REC-AD-002**: Anonymous LDAP (enumeration method)
- **REC-AD-003**: PowerView (comprehensive AD queries)
- **REC-AD-004**: SPN Scanning (correlate with service accounts)
- **CA-BRUTE-002**: Distributed Password Spraying (uses badPwdCount info)

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| Query badPwdCount | 1-2 minutes | Easy |
| Baseline collection | 5-10 minutes | Easy |
| Trend analysis | 5-15 minutes | Medium |
| Attack planning | 10+ minutes | Medium |
| **Total** | **20-40 minutes** | **Medium** |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
