# REC-CLOUD-004: AADInternals Tenant Reconnaissance

**SERVTEP ID:** REC-CLOUD-004  
**Technique Name:** AADInternals tenant reconnaissance  
**MITRE ATT&CK Mapping:** T1590 (Gather Victim Org Information)  
**CVE Reference:** N/A  
**Environment:** Entra ID  
**Severity:** Medium  
**Difficulty:** Easy  

---

## Executive Summary

AADInternals is a comprehensive PowerShell module for Azure Active Directory (Entra ID) reconnaissance and security testing. Developed for both red team operations and blue team defense validation, AADInternals provides low-level access to Entra ID APIs and enables extraction of tenant configuration, user information, federation details, and security settings without requiring elevated privileges. The module includes passive reconnaissance capabilities that require no authentication, making it ideal for initial tenant discovery and OSINT.

---

## Objective

Perform comprehensive Entra ID reconnaissance to identify:
- Tenant configuration and metadata
- User and group information
- Application and service principal inventory
- Federation and trust relationships
- Entra ID licensing and subscription information
- Security policy configuration
- Conditional Access policies
- Authentication methods and defaults
- Tenant-specific security gaps

---

## Prerequisites

- PowerShell 5.0+ or PowerShell Core
- AADInternals module from GitHub or PowerShell Gallery
- Entra ID credentials (optional for some functions—many work without auth)
- Internet connectivity to Microsoft Graph and Entra endpoints
- Execution policy bypass capability

---

## Execution Procedures

### Method 1: Installation and Initial Setup

**Step 1:** Install AADInternals module
```powershell
# Install from PowerShell Gallery
Install-Module -Name AADInternals -Force

# Alternatively, clone from GitHub
git clone https://github.com/Gerenios/AADInternals
cd AADInternals
Import-Module .\AADInternals.psd1 -Force

# Verify installation
Get-Command *AADInt* | Select-Object Name
```

**Step 2:** Bypass execution policy (if needed)
```powershell
# Check current execution policy
Get-ExecutionPolicy

# Bypass for current session
powershell -ExecutionPolicy Bypass -NoProfile

# Import module
Import-Module AADInternals
```

### Method 2: Passive Tenant Discovery (No Authentication)

**Step 1:** Enumerate tenant metadata
```powershell
# Get tenant ID from domain name (no auth required)
Get-AADIntTenantID -Domain "example.com"
# Returns: abcd1234-5678-9012-3456-789012345678

# Get detailed tenant information
Get-AADIntTenantDetails -Domain "example.com"
```

**Expected Output:**
```
Name                Value
---                 -----
Tenant ID           abcd1234-5678-9012-3456-789012345678
Organization Name   Example Organization
Default Domain      example.onmicrosoft.com
MFA Enabled         True
Skus                ENTERPRISE_MOBILITY_SUITE
```

**Step 2:** Enumerate authentication endpoints
```powershell
# Get OpenID configuration for tenant
Get-AADIntTenantOpenIDConfig -Domain "example.com"

# Get token endpoint information
$tenant = Get-AADIntTenantID -Domain "example.com"
Invoke-AADIntGraphRequest -Path "/organization" -TenantID $tenant
```

**Step 3:** Enumerate users and groups (unauthenticated)
```powershell
# Get user information (some endpoints accessible without auth)
Get-AADIntUsers -Domain "example.com"

# Get users with specific filters
Get-AADIntUsers -Domain "example.com" -Filter "startswith(displayName, 'admin')"

# Get external users/guests
Get-AADIntUsers -Domain "example.com" -Filter "userType eq 'Guest'"
```

### Method 3: Authenticated Reconnaissance

**Step 1:** Authenticate to Entra ID
```powershell
# Login interactively
$token = Get-AADIntAccessToken -ClientID "1b730954-1685-40b0-9b61-52078c018b8f"

# Or use device code (browser-based)
$token = Get-AADIntAccessTokenUsingDeviceCode

# Verify authentication
Invoke-AADIntGraphRequest -AccessToken $token -Path "/me"
```

**Step 2:** Comprehensive user enumeration
```powershell
# Get all users with detailed properties
$token = Get-AADIntAccessToken
$users = Get-AADIntUsers -AccessToken $token

$users | Select-Object displayName, userPrincipalName, mail, accountEnabled, createdDateTime

# Export users to CSV
$users | Export-Csv users.csv -NoTypeInformation

# Find privileged users
$users | Where-Object {$_.userType -eq "Member"} | 
  Where-Object {$_.mail -like "*admin*"}
```

**Step 3:** Enumerate groups and memberships
```powershell
# Get all groups
$groups = Get-AADIntGroups -AccessToken $token

# Get group members
$groupMembers = Get-AADIntGroupMembers -AccessToken $token -GroupID $group.id

# Find sensitive groups (Domain Admins equivalent)
$sensitiveGroups = Get-AADIntGroups -AccessToken $token | 
  Where-Object {$_.displayName -in @("Global Administrators", "Privileged Admins")}

# Export group structure
$groups | Select-Object displayName, id | Export-Csv groups.csv
```

### Method 4: Application and Service Principal Enumeration

**Step 1:** Enumerate registered applications
```powershell
# Get all applications
$apps = Get-AADIntApplications -AccessToken $token

# Get applications with API permissions
$appsWithPerms = $apps | Where-Object {$_.requiredResourceAccess -ne $null}

# Find applications with Graph API admin scopes
$dangerousApps = $appsWithPerms | Where-Object {
  $_.requiredResourceAccess.resourceAppId -contains "00000003-0000-0000-c000-000000000000"
}

# Export dangerous applications
$dangerousApps | Select-Object displayName, appId, id | Export-Csv dangerous_apps.csv
```

**Step 2:** Enumerate service principals
```powershell
# Get all service principals
$sps = Get-AADIntServicePrincipals -AccessToken $token

# Find service principals with roles
$roledSPs = $sps | Where-Object {$_.appRoleAssignments -ne $null}

# Get service principal admin roles
$adminSPs = $roledSPs | Where-Object {
  $_.appRoleAssignments.appRoleId -contains "62e90394-69f5-4237-9190-012177145e10"
}

# Export service principals with dangerous roles
$adminSPs | Select-Object displayName, appId, servicePrincipalType
```

### Method 5: Federation and Trust Enumeration

**Step 1:** Enumerate ADFS configuration
```powershell
# Get ADFS configuration (if federated)
Get-AADIntADFSConfiguration -Domain "example.com"

# Get federation service information
Get-AADIntFederationMetadata -Domain "example.com"

# Check if tenant is federated
$federationConfig = Get-AADIntFederationInfo -Domain "example.com"
if ($federationConfig.FederationServiceUrl) {
  Write-Host "Tenant is federated with ADFS:"
  $federationConfig.FederationServiceUrl
}
```

**Step 2:** Enumerate cross-tenant access
```powershell
# Get B2B collaboration settings
Get-AADIntB2BCollaborationSettings -AccessToken $token

# Get external user settings
Get-AADIntExternalUserSettings -AccessToken $token

# Find allowed external domains
Get-AADIntExternalUserDomains -AccessToken $token
```

### Method 6: Security Configuration Enumeration

**Step 1:** Check Conditional Access policies
```powershell
# Get Conditional Access policies
$caPolicy = Get-AADIntConditionalAccessPolicies -AccessToken $token

$caPolicy | Select-Object displayName, state, conditions | Format-List

# Identify disabled policies (security gaps)
$caPolicy | Where-Object {$_.state -eq "disabled"}
```

**Step 2:** Enumerate authentication policies
```powershell
# Get authentication methods
Get-AADIntAuthenticationMethods -AccessToken $token

# Check security defaults
Get-AADIntSecurityDefaults -AccessToken $token

# Get MFA enabled users
$mfaUsers = Get-AADIntMFAUsers -AccessToken $token
```

**Step 3:** Enumerate Entra ID roles
```powershell
# Get all directory roles
$roles = Get-AADIntDirectoryRoles -AccessToken $token

# Get role members for sensitive roles
$roles | ForEach-Object {
  $roleMembers = Get-AADIntDirectoryRoleMembers -AccessToken $token -RoleID $_.id
  Write-Host "$($_.displayName): $($roleMembers.count) members"
}
```

### Method 7: Advanced Reconnaissance Queries

**Step 1:** Extract tenant configuration details
```powershell
# Get organization information
$org = Invoke-AADIntGraphRequest -AccessToken $token -Path "/organization"

$org[0] | Select-Object displayName, id, verifiedDomains, 
  tenantType, marketingNotificationEmails

# Get licensing information
$licenses = Invoke-AADIntGraphRequest -AccessToken $token -Path "/subscribedSkus"

$licenses | Select-Object skuPartNumber, skuId, 
  @{N="Total Units";E={$_.prepaidUnits.enabled}}
```

**Step 2:** Enumerate company registration details
```powershell
# Get company details
Get-AADIntCompanyDetails -AccessToken $token

# Identify tenant type (Cloud-only vs. Hybrid)
if (Get-AADIntHybridConfiguration -AccessToken $token) {
  Write-Host "Hybrid configuration detected - check ADFS"
}
```

**Step 3:** Export comprehensive tenant profile
```powershell
$tenantProfile = @{
  "Tenant ID" = Get-AADIntTenantID -Domain "example.com"
  "Organization" = Invoke-AADIntGraphRequest -AccessToken $token -Path "/organization" | Select-Object -First 1
  "Users" = (Get-AADIntUsers -AccessToken $token).count
  "Groups" = (Get-AADIntGroups -AccessToken $token).count
  "Applications" = (Get-AADIntApplications -AccessToken $token).count
  "Licensing" = Invoke-AADIntGraphRequest -AccessToken $token -Path "/subscribedSkus" | Select-Object -First 1
  "Federated" = $null -ne (Get-AADIntFederationInfo -Domain "example.com")
}

$tenantProfile | ConvertTo-Json | Out-File tenant_profile.json
```

---

## Technical Deep Dive

### AADInternals Architecture

**Authentication Methods:**
1. Device Code Flow (browser-based, no password)
2. Username/Password (legacy)
3. Service Principal (cert/secret)
4. Refresh Token reuse
5. Unauthenticated queries (some endpoints public)

**Key APIs Leveraged:**
- Microsoft Graph API (`/graph.microsoft.com`)
- Azure AD Portal APIs (internal)
- OpenID Connect endpoints
- ADFS metadata endpoints

### Tenant Information Retrieval

| Data | Authentication | Risk |
|------|---|---|
| Tenant ID | None | Low |
| Organization name | None | Low |
| Domain names | None | Low |
| User enumeration | Required | High |
| Group membership | Required | High |
| Role assignments | Required | Critical |
| Application secrets | Required | Critical |

---

## Detection Strategies (Blue Team)

### AADInternals Detection

1. **Module Import Logging**
   ```
   Event ID 4103: Module Logging
   Alert on: AADInternals module import
   Signature: Get-AADInt* function execution
   ```

2. **Graph API Pattern Recognition**
   - Bulk user/group/application enumeration
   - Token request patterns (device code, refresh token)
   - Unusual API query sequences

3. **Authentication Logging**
   - Non-interactive sign-ins with device code
   - Sign-ins from unusual locations
   - Service principal authentication spikes

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Stealth Enumeration**
   - Use device code flow (harder to track)
   - Space API queries across time
   - Use low-privilege user account

2. **Artifact Removal**
   - Delete PowerShell history
   - Remove module imports from logs
   - Clear browser history

### Defensive Measures

1. **PowerShell Logging**
   - Enable script block logging
   - Monitor for AADInternals module import
   - Alert on Get-AADInt* function execution

2. **Graph API Monitoring**
   - Implement rate limiting
   - Alert on bulk enumeration patterns
   - Monitor for device code abuse

---

## Mitigation Strategies

1. **Detection & Response**
   - Enable Azure AD Sign-in Logs
   - Monitor Graph API audit trails
   - Alert on bulk enumeration

2. **Access Controls**
   - Restrict device code flow usage
   - Limit Graph API access
   - Implement Conditional Access policies

3. **Long-term Security**
   - Regular tenant security audits
   - RBAC least-privilege principle
   - Disable unused service principals

---

## References & Further Reading

- [AADInternals GitHub Repository](https://github.com/Gerenios/AADInternals)
- [AADInternals PowerShell Gallery](https://www.powershellgallery.com/packages/AADInternals)
- [Microsoft Graph API Documentation](https://learn.microsoft.com/en-us/graph/overview)
- [Entra ID Security Best Practices](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-introduction)

---

## Related SERVTEP Techniques

- **REC-AD-001**: Tenant Discovery via domain properties
- **REC-CLOUD-001**: BloodHound (privilege path analysis)
- **REC-CLOUD-002**: ROADtools (Entra ID enumeration)
- **REC-M365-001**: Microsoft Graph API enumeration

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| Module installation | 2-5 minutes | Easy |
| Passive enumeration | 1-3 minutes | Easy |
| Authentication | 1-2 minutes | Easy |
| User/group discovery | 2-5 minutes | Easy |
| Application enumeration | 2-5 minutes | Easy |
| Full reconnaissance | 10-20 minutes | Easy |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
