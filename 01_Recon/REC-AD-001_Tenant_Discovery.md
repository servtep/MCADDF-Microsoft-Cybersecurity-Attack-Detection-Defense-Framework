# REC-AD-001: Tenant Discovery via Domain Properties

**SERVTEP ID:** REC-AD-001  
**Technique Name:** Tenant Discovery via domain properties  
**MITRE ATT&CK Mapping:** T1590.001 (Gather Victim Org Information - Identify Cloud Tenants)  
**CVE Reference:** N/A  
**Environment:** Entra ID  
**Severity:** Medium  
**Difficulty:** Easy  

---

## Executive Summary

Tenant discovery via domain properties is a passive reconnaissance technique that extracts critical Entra ID tenant metadata without authentication. By querying DNS records, HTTPS responses, and cloud service endpoints, attackers can identify target tenant IDs, tenant names, and associated cloud services. This technique serves as the foundation for subsequent Azure/Entra ID enumeration attacks.

---

## Objective

Discover and validate Entra ID tenant metadata including:
- Tenant ID (GUID)
- Tenant name and organizational domain
- Associated cloud services (Azure, Microsoft 365, Dynamics)
- Federated identity providers
- OAuth endpoints and authorization servers
- Tenant-specific service endpoints

---

## Prerequisites

- Network access to public DNS and web services
- Standard HTTP/HTTPS client utilities (curl, wget, browser)
- No authentication required
- Target domain or organizational email address (optional)

---

## Execution Procedures

### Method 1: DNS TXT Record Enumeration

**Step 1:** Query DNS TXT records for tenant discovery domains
```bash
# Query Microsoft's service discovery records
nslookup -type=TXT _acct.example.com
nslookup -type=TXT _dmarc.example.com
nslookup -type=TXT default._domainkey.example.com

# Use dig for detailed enumeration
dig +short TXT example.com
dig +short TXT _domainkey.example.com
```

**Step 2:** Extract SPF, DMARC, and DKIM records
```bash
# These often reveal cloud service providers
host -t TXT example.com
```

**Expected Output:** DNS records containing references to Microsoft services:
```
v=spf1 include:outlook.com ~all
v=DMARC1; p=quarantine; rua=mailto:...
```

### Method 2: HTTPS Endpoint Discovery

**Step 1:** Query Entra ID autodiscovery endpoints
```bash
# Query tenant discovery endpoint
curl -s https://login.microsoftonline.com/common/discovery/v2.0/keys

# Query tenant-specific OpenID configuration
curl -s https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration
```

**Step 2:** Use Entra ID common discovery endpoint
```bash
curl -s https://login.microsoftonline.com/common/.well-known/openid-configuration | jq .
```

**Expected JSON Response:**
```json
{
  "token_endpoint": "https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token",
  "authorization_endpoint": "https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/authorize",
  "issuer": "https://login.microsoftonline.com/{tenant-id}/v2.0",
  "tenant_region_scope": "EU",
  "cloud_instance_name": "microsoftonline.com"
}
```

### Method 3: SharePoint Tenant Discovery

**Step 1:** Query SharePoint autodiscovery
```bash
# Query tenant discovery for SharePoint Online
curl -s https://example.sharepoint.com/_vti_bin/ListData.svc/ -H "Authorization: Bearer invalid" 2>&1 | grep -i tenant

# Use discoveryUrl pattern
curl -s https://example-my.sharepoint.com/
```

**Step 2:** Extract tenant GUID from response headers
```bash
curl -I https://example.sharepoint.com/ | grep -i "x-msaag" | grep -i "tenantid"
```

### Method 4: Microsoft Graph API Reconnaissance

**Step 1:** Query public metadata endpoints
```bash
# Access Graph metadata without authentication
curl -s https://graph.microsoft.com/v1.0/me/
# Returns error but reveals tenant info in error messages

# Query discovery service
curl -s "https://login.microsoftonline.com/common/discovery/v2.0/keys?appid={app_id}"
```

**Step 2:** Enumerate service principals via public endpoints
```bash
# Query well-known tenant discovery endpoint
curl -s https://login.windows.net/{tenant-id}/.well-known/openid-configuration
```

### Method 5: Web Application Reconnaissance

**Step 1:** Examine login pages and responses
```bash
# Query Office 365 login page
curl -s "https://login.microsoftonline.com/common/login" -d "username=user@example.com&password=test" 2>&1 | grep -i "tenant\|realm"
```

**Step 2:** Check authentication response headers
```bash
curl -I https://outlook.office365.com/
# Look for Set-Cookie headers containing tenant references
```

### Method 6: Automated Tenant Discovery Tools

**Using AADInternals PowerShell Module:**
```powershell
# Requires AADInternals module
Import-Module AADInternals

# Discover tenant ID from domain
Get-AADIntTenantID -Domain "example.com"

# Get tenant information
Get-AADIntTenantDetails -Domain "example.com"
```

**Using PowerShell Direct Method:**
```powershell
$domain = "example.com"
$response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$domain/.well-known/openid-configuration" -Method GET
$response | ConvertTo-Json
```

### Method 7: Email Validation Response Mining

**Step 1:** Submit invalid credentials to Office 365
```bash
# Query Office 365 login validation
curl -s "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com"}' | jq .
```

**Expected Response Reveals:**
```json
{
  "IfExistsResult": 0,
  "Credentials": {
    "PrimaryAuthenticationMethod": 3,
    "FederationRedirectUrl": "https://..."
  },
  "ThrottleStatus": 0
}
```

### Method 8: DNS CNAME Chain Analysis

**Step 1:** Trace CNAME records to Microsoft services
```bash
nslookup example.onmicrosoft.com
nslookup example.mail.protection.outlook.com
nslookup example-my.sharepoint.com
```

**Step 2:** Parse responses for tenant identifiers
```bash
# Azure CDN endpoints contain tenant references
dig CNAME example.azureedge.net +short
```

---

## Technical Deep Dive

### Tenant ID Extraction

The Entra ID tenant ID (a 32-character GUID) is discoverable through:

1. **OpenID Connect Metadata:** `.well-known/openid-configuration` endpoints expose tenant GUID in issuer URL:
   ```
   https://login.microsoftonline.com/12345678-1234-1234-1234-123456789012/v2.0
   ```

2. **JWT Token Claims:** Any valid Entra ID token decoded reveals `tid` claim with tenant GUID

3. **Service Endpoints:** Azure management APIs expose tenant information:
   ```
   https://management.azure.com/subscriptions/?api-version=2020-01-01
   ```

### Federation Detection

**ADFS Indicator:** Presence of `FederationRedirectUrl` in Office 365 credential check response indicates hybrid federation setup:
```json
"FederationRedirectUrl": "https://adfs.example.com/adfs/ls/"
```

**SAML Endpoints:** Queries to `.../saml2` endpoints reveal ADFS/SAML identity providers

### Cloud Regions

Tenant responses reveal cloud deployment region:
- `microsoftonline.com` = Commercial cloud (WW)
- `microsoftonline.us` = Government Cloud (GCC High)
- `microsoftonline.de` = Germany Cloud
- `microsoftonline.cn` = China Cloud (21Vianet)

---

## Detection Strategies (Blue Team)

### Network-Based Detection

1. **DNS Query Monitoring**
   - Alert on repeated queries to Microsoft domain discovery services
   - Monitor for enumeration patterns against `.well-known` endpoints
   - Flag bulk queries to `.sharepoint.com` domains

2. **HTTP/HTTPS Traffic Analysis**
   - Log all requests to `login.microsoftonline.com` without subsequent authentication
   - Monitor for `.well-known/openid-configuration` scanning
   - Detect credential validation probes (high volume of failed login attempts)

### Endpoint Detection

1. **PowerShell Logging**
   ```
   Event ID 4104: Script block execution logging
   Alert on: Get-AADIntTenantID, AADInternals module imports
   ```

2. **Network Namespace Tracking**
   ```
   Monitor for: Invoke-RestMethod to Microsoft discovery endpoints
   Trigger on: Repeated requests to /common/GetCredentialType
   ```

### SIEM Signatures

```
Title: Entra ID Tenant Discovery Attempt
Event: DNS query + HTTP GET to login.microsoftonline.com/.well-known/* within 5 minutes
Severity: Low (reconnaissance phase)
```

### Microsoft Sentinel Rules

Create detection rule for:
```kusto
let DiscoveryEndpoints = dynamic([
  "login.microsoftonline.com",
  "graph.microsoft.com",
  ".sharepoint.com"
]);
AppServiceHTTPLogs
| where Uri has_any (DiscoveryEndpoints)
  and Uri contains ".well-known"
  and ResponseCode == 200
  and HttpMethod == "GET"
| summarize Count = count() by ClientIP, Uri
| where Count > 10
```

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **DNS Enumeration Stealth**
   - Use distributed DNS queries across multiple resolver IPs
   - Rotate user-agents when querying HTTPS endpoints
   - Avoid suspicious HTTP header patterns

2. **Rate Limiting**
   - Space queries 5-10 seconds apart
   - Vary query patterns (DNS, HTTPS, Graph API alternating)
   - Use proxy chains to obfuscate source IP

3. **Timing**
   - Conduct reconnaissance during business hours to blend with legitimate traffic
   - Distribute queries across multiple days

### Defensive Measures

1. **DNS Sinkholing**
   - Implement DNS filtering for known reconnaissance tools
   - Monitor for unusual patterns in DNS query logs

2. **API Rate Limiting**
   - Enforce rate limits on credential validation endpoints (max 5 requests/IP/min)
   - Implement backoff strategies for failed authentication attempts

3. **Disable Public Metadata**
   - Consider disabling public `/.well-known/` endpoints (not recommended—breaks standards compliance)
   - Implement WAF rules to limit metadata endpoint access

---

## Mitigation Strategies

1. **For Organizations**
   - Enable tenant restrictions in Conditional Access to prevent unauthorized access
   - Monitor and alert on tenant discovery attempts
   - Implement DNS filtering for internal reconnaissance tools
   - Use Azure Firewall/WAF to rate-limit metadata endpoints

2. **For Security Teams**
   - Baseline tenant metadata queries during normal operations
   - Alert on discovery patterns matching known attack tools
   - Implement external attack surface management (EASM) to identify exposed metadata

3. **For Developers**
   - Document legitimate tenant discovery requirements
   - Implement API authentication even for "public" endpoints
   - Avoid exposing tenant identifiers in error messages

---

## References & Further Reading

- [Microsoft Entra ID Tenant Properties Documentation](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-whatis)
- [OpenID Connect Discovery Specification](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [T1590.001 - MITRE ATT&CK Gathering Victim Org Information](https://attack.mitre.org/techniques/T1590/001/)
- [AADInternals GitHub Repository](https://github.com/Gerenios/AADInternals)
- [Microsoft Identity Platform Endpoints](https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols)

---

## Related SERVTEP Techniques

- **REC-CLOUD-002**: ROADtools Entra ID enumeration (authenticated follow-up)
- **REC-CLOUD-004**: AADInternals tenant reconnaissance (comprehensive tenant profiling)
- **IA-PHISH-001**: Device code phishing (leverages discovered tenant metadata)
- **CA-TOKEN-001**: Hybrid AD cloud token theft (requires tenant discovery as prerequisite)

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| Initial reconnaissance | < 1 minute | Trivial |
| Tenant ID extraction | < 2 minutes | Easy |
| Service endpoint mapping | 2-5 minutes | Easy |
| Federation detection | 1-3 minutes | Easy |
| **Total** | **5-11 minutes** | **Easy** |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
