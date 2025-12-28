# REC-AD-003: PowerView Enumeration for Domain Mapping

**SERVTEP ID:** REC-AD-003  
**Technique Name:** PowerView enumeration for domain mapping  
**MITRE ATT&CK Mapping:** T1087.002 (Account Discovery - Domain Account)  
**CVE Reference:** N/A  
**Environment:** Windows Active Directory  
**Severity:** High  
**Difficulty:** Medium  

---

## Executive Summary

PowerView is an advanced reconnaissance framework written in PowerShell that enables comprehensive Active Directory enumeration and trust relationship mapping. Developed as part of the PowerSploit toolset, PowerView provides a user-friendly interface to Active Directory queries, group policy enumeration, and domain trust visualization. Unlike raw LDAP queries, PowerView includes sophisticated filtering, trust analysis, and privilege escalation path identification—making it the de facto standard for AD reconnaissance during both authorized penetration tests and adversarial campaigns.

---

## Objective

Conduct comprehensive Active Directory reconnaissance using PowerView to:
- Map domain structure and organizational hierarchy
- Identify privilege escalation paths
- Enumerate trust relationships across forests
- Locate service accounts with delegation privileges
- Extract group policy configurations
- Identify vulnerable access control lists (ACLs)
- Find unexpected administrative access
- Map computer-to-user relationships

---

## Prerequisites

- Windows system with PowerShell 3.0+ (or 2.0 with appropriate .NET)
- Domain-joined or unauthenticated network access to domain controllers
- PowerView script (powerview.ps1) from PowerSploit project
- Local administrator preferred (some functions require elevated privileges)
- Execution policy bypass or appropriate permissions
- Optional: Mimikatz, Bloodhound for follow-up analysis

---

## Execution Procedures

### Method 1: PowerView Script Execution & Basic Enumeration

**Step 1:** Load PowerView module
```powershell
# Bypass execution policy
powershell -ExecutionPolicy Bypass -NoProfile

# Import PowerView
. .\powerview.ps1

# Verify import succeeded
Get-Command | grep -i "Get-Net" | Select-Object Name
```

**Step 2:** Enumerate domain information
```powershell
# Get domain information
Get-NetDomain

# Get domain forest
Get-NetForest

# Get all domains in forest
Get-NetForest | Select-Object Domains

# Enumerate all domain controllers
Get-NetDomainController

# Get domain policy
Get-DomainPolicyData
```

**Example Output:**
```
Name: example.com
Forest: example.com
DomainControllers: 3
FunctionalLevel: 2016
```

**Step 3:** Enumerate all user accounts
```powershell
# Get all users in domain
Get-NetUser | Select-Object samAccountName, mail, displayName, userAccountControl

# Find enabled users only
Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | Select-Object samAccountName, mail

# Find users with password never expires
Get-NetUser -UACFilter DONT_EXPIRE_PASSWD | Select-Object samAccountName, displayName

# Search for specific user patterns (service accounts)
Get-NetUser | Where-Object {$_.samAccountName -like "*svc*"} | Select-Object samAccountName

# Export to CSV
Get-NetUser | Select-Object samAccountName, mail, displayName, pwdLastSet | Export-Csv users.csv
```

**Step 4:** Enumerate groups and memberships
```powershell
# Get all groups
Get-NetGroup | Select-Object samAccountName, description

# Find "Domain Admins" members
Get-NetGroup -GroupName "Domain Admins" | Select-Object member

# Get all members of sensitive groups
Get-NetGroup "Domain Admins", "Enterprise Admins", "Schema Admins" | 
  ForEach-Object { Get-NetGroupMember -GroupName $_.samAccountName }

# Recursively resolve nested group memberships
Get-NetGroup | ForEach-Object {
  Get-NetGroupMember -GroupName $_.samAccountName -Recurse
} | Select-Object memberName, groupName

# Find groups with no explicit members but inherited privileges
Get-NetGroup | Where-Object {$_.member -eq $null}
```

### Method 2: Privilege Escalation Path Enumeration

**Step 1:** Identify accounts with dangerous delegation
```powershell
# Get accounts with constrained delegation
Get-NetUser -AllowDelegation | 
  Where-Object {$_.trustedforDelegation -eq $true} |
  Select-Object samAccountName, servicePrincipalName

# Find unconstrained delegation (highest privilege)
Get-NetComputer -Unconstrained | 
  Select-Object samAccountName, operatingSystem, dNSHostName

# Get computers with resource-based constrained delegation (RBCD)
Get-NetComputer | Where-Object {$_.msds-allowedtoactonbehalfofotheridentity -ne $null}
```

**Step 2:** Enumerate service principal names (SPNs)
```powershell
# Find all SPNs in domain (potential kerberoasting targets)
Get-NetUser -SPN | Select-Object samAccountName, servicePrincipalName

# Get computers with SPNs
Get-NetComputer -SPN | Select-Object samAccountName, dNSHostName, servicePrincipalName

# Identify Exchange servers (common target)
Get-NetUser -SPN | Where-Object {$_.servicePrincipalName -like "*HTTP*"}

# Filter for accounts without password-required flag
Get-NetUser -SPN | 
  Where-Object {$_.userAccountControl -band 0x400000} |
  Select-Object samAccountName, servicePrincipalName
```

**Step 3:** Find ACL-based privilege paths
```powershell
# Get ACLs on domain object (identify who can reset passwords)
Get-ObjectAcl -Identity "CN=Users,DC=example,DC=com" -ResolveGUIDs |
  Select-Object ActiveDirectoryRights, ObjectAceType, IdentityReference

# Find all users with GenericAll rights on other users
Get-ObjectAcl -SearchBase "CN=Users,DC=example,DC=com" -ResolveGUIDs |
  Where-Object {$_.ActiveDirectoryRights -eq "GenericAll"} |
  Select-Object IdentityReference, ObjectDN

# Identify DCSync-capable accounts (can dump hashes)
Get-ObjectAcl -SearchBase "DC=example,DC=com" -ResolveGUIDs -Filter "(IdentityReference=*)" |
  Where-Object {($_.ObjectAceType -eq "DS-Replication-Get-Changes") -or 
                ($_.ObjectAceType -eq "DS-Replication-Get-Changes-All")} |
  Select-Object IdentityReference, ObjectDN
```

### Method 3: Trust Relationship Mapping

**Step 1:** Enumerate domain trusts
```powershell
# Get all trusts for current domain
Get-NetDomainTrust | Select-Object TargetName, TrustType, TrustDirection

# Map forest-wide trusts
Get-NetForest | Select-Object -ExpandProperty Domains | 
  ForEach-Object { Get-NetDomainTrust -Domain $_ }

# Identify external trusts (highest risk)
Get-NetDomainTrust | Where-Object {$_.TrustType -eq "External"}

# Find bidirectional trusts (allow pass-the-hash/ticket attacks)
Get-NetDomainTrust | Where-Object {$_.TrustDirection -eq "Bidirectional"}
```

**Step 2:** Enumerate trust credentials and relationships
```powershell
# Get trust account credentials (lsass memory extraction required)
Get-NetDomainTrust -Credentials (Get-Credential)

# Identify trusting domains vulnerable to SID History manipulation
Get-NetForest | Select-Object -ExpandProperty Domains |
  ForEach-Object { 
    Write-Host "Domain: $_"
    Get-NetDomainTrust -Domain $_
  }
```

### Method 4: Computer and Share Enumeration

**Step 1:** Map network computers
```powershell
# Get all computers in domain
Get-NetComputer | Select-Object samAccountName, dNSHostName, operatingSystem

# Filter for servers only
Get-NetComputer -Filter "operatingSystem=*Server*" |
  Select-Object samAccountName, dNSHostName, operatingSystem

# Get computers with unusual last logon times (potential honeypots)
Get-NetComputer | Where-Object {$_.lastLogonTimestamp -lt (Get-Date).AddDays(-30)} |
  Select-Object samAccountName, dNSHostName, lastLogonTimestamp

# Identify offline computers (vulnerable to pass-the-hash without detection)
Get-NetComputer -Ping | Select-Object samAccountName, dNSHostName
```

**Step 2:** Enumerate shared resources
```powershell
# Find all network shares across domain
Get-NetShare

# Enumerate shares on specific computer
Get-NetShare -ComputerName "server01.example.com"

# Identify high-risk shares (ADMIN$, C$, IPC$)
Get-NetShare | Where-Object {$_.Name -in @("ADMIN$", "C$", "IPC$")}

# Find shares with weak permissions
Get-NetShare | Where-Object {$_.Permissions -like "*Everyone*"}
```

### Method 5: Group Policy Enumeration

**Step 1:** Extract GPO configurations
```powershell
# Get all GPOs
Get-NetGPO | Select-Object displayName, dn, gpcFileSysPath

# Find GPOs with scheduled tasks (potential lateral movement vectors)
Get-NetGPO | Where-Object {$_.gpcFileSysPath -like "*ScheduledTasks*"}

# Enumerate GPO permissions
Get-NetGPOGroup | Select-Object groupName, gpoName, permissions

# Find GPOs applied to sensitive groups
Get-NetGPOGroup | Where-Object {$_.groupName -in @("Domain Admins", "Enterprise Admins")}

# Extract GPO scripts and logon scripts
Get-NetGPO | ForEach-Object {
  $gpoPath = $_.gpcFileSysPath
  Get-ChildItem -Path "$gpoPath\User\Scripts" -Recurse -ErrorAction SilentlyContinue
}
```

**Step 2:** Find GPO-based persistence opportunities
```powershell
# Identify GPOs with weak edit permissions
Get-ObjectAcl -Identity (Get-NetGPO | Select-Object -First 1).dn -ResolveGUIDs |
  Where-Object {$_.ActiveDirectoryRights -like "*Write*"}

# Find GPOs applied to computers where current user is admin
# (can be leveraged for persistence)
Get-NetOU | ForEach-Object {
  Get-NetComputer -OU $_.dn | ForEach-Object {
    $computer = $_
    # Check if user has admin access (requires additional checks)
  }
}
```

### Method 6: Advanced Reconnaissance Techniques

**Step 1:** Identify computer-to-user session mapping
```powershell
# Get active sessions on computers (requires network access)
Get-NetSession -ComputerName "server01" | 
  Select-Object userName, ComputerName, idleTime

# Find logged-in users across all computers (time-intensive)
Get-NetComputer | ForEach-Object {
  Get-NetSession -ComputerName $_.dNSHostName -ErrorAction SilentlyContinue
}
```

**Step 2:** Identify weak delegation configurations
```powershell
# Find constrained delegation without protocol transition
Get-NetUser -AllowDelegation |
  Where-Object {$_.trustedtoauthfordelegation -eq $false} |
  Select-Object samAccountName, msds-allowedtoactonbehalfofotheridentity

# Computers with RBCD misconfiguration
Get-NetComputer | ForEach-Object {
  $rbcd = Get-ObjectAcl -Identity $_.distinguishedName -ResolveGUIDs |
    Where-Object {$_.ObjectAceType -like "*AllowedToActOnBehalfOfOtherIdentity*"}
  if ($rbcd) {
    Write-Host "$($_.samAccountName) has RBCD configured"
    $rbcd | Select-Object IdentityReference
  }
}
```

**Step 3:** Export findings for Bloodhound analysis
```powershell
# PowerView data can feed into Bloodhound
# Save enumeration data to structured format
$users = Get-NetUser | Select-Object @{N='SAMAccountName';E={$_.samAccountName}},
  @{N='Mail';E={$_.mail}},
  @{N='Enabled';E={-not ($_.userAccountControl -band 2)}}

$groups = Get-NetGroup | Select-Object @{N='Name';E={$_.samAccountName}},
  @{N='Description';E={$_.description}}

$computers = Get-NetComputer | Select-Object @{N='Name';E={$_.samAccountName}},
  @{N='OS';E={$_.operatingSystem}},
  @{N='DNSHostName';E={$_.dNSHostName}}

# Export for analysis
$users | Export-Csv users_export.csv -NoTypeInformation
$groups | Export-Csv groups_export.csv -NoTypeInformation
$computers | Export-Csv computers_export.csv -NoTypeInformation
```

---

## Technical Deep Dive

### PowerView Architecture

PowerView leverages Active Directory APIs through:

1. **DirectoryServices (.NET Framework):** LDAP queries and object manipulation
2. **DirectorySearcher:** Filtering and attribute extraction
3. **PrincipalContext:** User and group operations
4. **NetAPI32 interop:** Session and share enumeration

### Critical PowerView Functions

| Function | Purpose | Risk Level |
|----------|---------|-----------|
| `Get-NetDomain` | Domain metadata | Low |
| `Get-NetUser` | User enumeration | Medium |
| `Get-NetGroup` | Group enumeration | Medium |
| `Get-ObjectAcl` | ACL extraction | High |
| `Get-NetDomainTrust` | Trust mapping | High |
| `Get-NetGPO` | GPO enumeration | High |
| `Invoke-ShareFinder` | Network share discovery | High |

### Detection Evasion Techniques

PowerView avoids some traditional detection by:
- Using built-in .NET APIs (not ldapsearch.exe)
- No binary execution (PowerShell in-memory)
- Flexible filtering options to avoid suspicious queries
- Can use encrypted credentials for authentication

---

## Detection Strategies (Blue Team)

### PowerShell Logging

1. **Module Import Logging**
   ```
   Event ID 4103: Module Logging
   Alert on: PowerView.ps1 import, function execution
   Signature: Get-NetUser, Get-NetGroup, Get-ObjectAcl execution patterns
   ```

2. **Script Block Logging**
   ```
   Event ID 4104: Script Block Execution Logging
   Pattern: Repeating Get-Net* calls within 5-second window
   Severity: Trigger on 20+ enumeration calls per minute
   ```

3. **Command Line Logging**
   ```
   Event ID 4688: Process Creation
   Parent: powershell.exe
   Alert on: PowerView.ps1 in command line or script block
   ```

### SIEM Detection Rules

```kusto
SecurityEvent
| where EventID == 4104
| where ScriptBlockText contains "Get-Net" or ScriptBlockText contains "powerview"
| where ScriptBlockText contains_cs "Domain" or ScriptBlockText contains_cs "User"
| summarize Count = count() by UserName, Computer, bin(TimeGenerated, 1m)
| where Count > 20
```

### EDR Signatures

- Monitor for in-process LDAP query patterns
- Alert on DirectoryServices namespace usage in unusual contexts
- Detect enumeration of sensitive AD objects (Exchange, MSSQL)
- Track access to domain trust attributes

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Execution Methods**
   - Load PowerView in-memory to avoid disk artifacts
   - Use `-EncodedCommand` to obfuscate scripts
   - Execute via legitimate remote tools (PSExec, WinRM)

2. **Timing & Stealth**
   - Space enumeration calls across hours/days
   - Avoid queries that trigger alerts (ACL, trust, GPO functions)
   - Use alternate tools (BloodHound, AdFind) to diversify fingerprint

3. **OPSEC-aware Modifications**
   - Rename functions to avoid signature detection
   - Comment out verbose output
   - Disable output-to-file to prevent logging

### Defensive Measures

1. **Execution Policy Enforcement**
   ```powershell
   # Enforce signed scripts only
   Set-ExecutionPolicy AllSigned
   ```

2. **PowerShell Logging**
   ```powershell
   # Enable module and script block logging
   Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
     -Name "EnableModuleLogging" -Value 1
   ```

3. **Behavioral Analytics**
   - Monitor for bulk LDAP queries from unexpected sources
   - Alert on DirectoryServices API abuse
   - Track suspicious PowerShell module imports

---

## Mitigation Strategies

1. **Detection & Response**
   - Enable PowerShell module and script block logging
   - Monitor for Get-Net* function execution
   - Alert on bulk enumeration patterns

2. **Access Controls**
   - Restrict PowerShell execution on non-admin systems
   - Limit domain user account permissions
   - Use Constrained Language Mode for regular users

3. **Hardening**
   - Disable unused accounts and groups
   - Remove unnecessary delegation privileges
   - Implement principle of least privilege for AD object access

---

## References & Further Reading

- [PowerSploit GitHub Repository](https://github.com/PowerShellMafia/PowerSploit)
- [PowerView Function Documentation](https://github.com/PowerShellMafia/PowerSploit/wiki/PowerView)
- [T1087.002 - MITRE ATT&CK Account Discovery](https://attack.mitre.org/techniques/T1087/002/)
- [Active Directory Security Hardening Guide](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)

---

## Related SERVTEP Techniques

- **REC-AD-001**: Tenant discovery (Entra ID equivalent)
- **REC-AD-002**: Anonymous LDAP (unauthenticated alternative)
- **REC-AD-004**: SPN scanning (builds on PowerView user enumeration)
- **REC-CLOUD-001**: BloodHound (Entra ID privilege path analysis)
- **PE-TOKEN-002**: RBCD exploitation (uses PowerView ACL discovery)

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| PowerView load | < 30 seconds | Trivial |
| Domain enumeration | 1 minute | Easy |
| User/group discovery | 2-5 minutes | Easy |
| Trust mapping | 2-3 minutes | Medium |
| ACL analysis | 5-10 minutes | Medium |
| Full reconnaissance | 15-30 minutes | Medium |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
