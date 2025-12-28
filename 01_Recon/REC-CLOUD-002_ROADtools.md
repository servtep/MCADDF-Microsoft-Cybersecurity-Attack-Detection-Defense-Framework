# REC-CLOUD-002: ROADtools Entra ID Enumeration

**SERVTEP ID:** REC-CLOUD-002  
**Technique Name:** ROADtools Entra ID enumeration  
**MITRE ATT&CK Mapping:** T1087.004 (Account Discovery - Cloud Account)  
**CVE Reference:** N/A  
**Environment:** Entra ID  
**Severity:** High  
**Difficulty:** Easy  

---

## Executive Summary

ROADtools is a lightweight, Python-based toolkit for Microsoft Entra ID (formerly Azure AD) reconnaissance and enumeration. Unlike BloodHound which requires full database infrastructure, ROADtools provides rapid command-line enumeration of Entra ID users, applications, roles, and permissions without requiring extensive setup. The tool's TokenStorage feature enables persistent access and token manipulation, making it ideal for rapid reconnaissance during the initial access phase or for low-and-slow enumeration to avoid detection.

---

## Objective

Rapidly enumerate Entra ID configuration and identify escalation opportunities:
- User and group enumeration
- Application inventory and permission analysis
- Service principal discovery and trust relationships
- Entra ID role assignments
- Conditional Access policies
- Authentication policies and security defaults
- Azure subscription and resource enumeration
- API exposure and misconfiguration

---

## Prerequisites

- Python 3.6+ with pip
- ROADtools GitHub repository or PyPI package
- Entra ID credentials (any user account works for enumeration)
- Azure CLI installed (optional but helpful)
- Internet connectivity to Microsoft Graph and Entra endpoints

---

## Execution Procedures

### Method 1: Installation and Initial Setup

**Step 1:** Install ROADtools
```bash
# Clone repository
git clone https://github.com/dirkjanm/roadtools
cd roadtools

# Install dependencies
pip install -r requirements.txt

# Alternatively, install via PyPI
pip install roadtools

# Verify installation
roadrecon --version
```

**Step 2:** Authenticate to Entra ID
```bash
# Authenticate with device code flow (works from any network)
roadrecon auth -t {tenant-id}

# Follow authentication prompt in browser
# Token saved to ~/.roadtools_auth

# Verify authentication
roadrecon whoami
```

### Method 2: User and Group Enumeration

**Step 1:** Enumerate all Entra ID users
```bash
# List all users
roadrecon users

# Export users to JSON
roadrecon users -o users.json

# Get users with specific properties
roadrecon users --select "id,displayName,userPrincipalName,accountEnabled"
```

**Step 2:** Extract user-specific information
```bash
# Get user with detailed information
roadrecon users -f "displayName eq 'John Admin'" --expand

# Query users with specific attributes
roadrecon users --filter "assignedLicenses/any(x:true)" --select "displayName,mail"

# Find external users (B2B guests)
roadrecon users -f "userType eq 'Guest'"

# Get users with administrative roles
roadrecon users --filter "givenName eq null" --select "displayName,mail,id"
```

**Step 3:** Enumerate groups and memberships
```bash
# List all groups
roadrecon groups

# Get group members
roadrecon groups -g {group-id} --expand members

# Export group structure
roadrecon groups -o groups.json

# Find groups with many members (potential privilege paths)
roadrecon groups --select "displayName,mail,memberCount"
```

### Method 3: Application and Service Principal Enumeration

**Step 1:** Enumerate registered applications
```bash
# List all applications
roadrecon applications

# Get application details
roadrecon applications -a {app-id} --expand

# Export to CSV for analysis
roadrecon applications --csv applications.csv

# Find applications with API permissions
roadrecon applications --filter "requiredResourceAccess/any(x:true)" --select "displayName,appId,id"
```

**Step 2:** Enumerate service principals
```bash
# List all service principals
roadrecon serviceprincipals

# Export service principal details
roadrecon serviceprincipals -o serviceprincipals.json

# Find service principals with dangerous permissions
roadrecon serviceprincipals --filter "appRoleAssignments/any(x:true)"

# Get service principal admin consent grants
roadrecon serviceprincipals -s {sp-id} --expand oauth2PermissionGrants
```

**Step 3:** Find risky applications
```bash
# Applications with Graph API admin permissions
roadrecon applications --filter "requiredResourceAccess/any(ra: ra/resourceAppId eq '00000003-0000-0000-c000-000000000000')" \
  --select "displayName,appId"

# Service principals with Owner/Admin roles
roadrecon serviceprincipals --filter "appRoleAssignments/any(x: x/appRoleId eq '62e90394-69f5-4237-9190-012177145e10')"
```

### Method 4: Role and Permission Analysis

**Step 1:** Enumerate Entra ID roles
```bash
# List all directory roles
roadrecon roles

# Get role members
roadrecon roles -r {role-id} --expand members

# Find users with privileged roles
roadrecon roles --filter "displayName eq 'Global Administrator'" --expand members
```

**Step 2:** Analyze role assignments
```bash
# Get direct role assignments for user
roadrecon users -u {user-id} --expand memberOf

# Find members of sensitive groups
roadrecon groups -g "Global Administrator" --expand members

# Export role hierarchy
roadrecon roles --select "displayName,id,description" -o roles.json
```

**Step 3:** Enumerate managed identities
```bash
# List managed identities
roadrecon managedidentities

# Get MI role assignments
roadrecon managedidentities -m {mi-id} --expand roleAssignments

# Find MIs with dangerous roles
roadrecon managedidentities --filter "roleAssignments/any(x: x/roleId eq '62e90394-69f5-4237-9190-012177145e10')"
```

### Method 5: Conditional Access and Policy Enumeration

**Step 1:** Enumerate Conditional Access policies
```bash
# List all CA policies
roadrecon conditionalaccess

# Export CA policies
roadrecon conditionalaccess -o ca_policies.json

# Find policies with weak requirements
roadrecon conditionalaccess --select "displayName,id,conditions,grantControls"
```

**Step 2:** Identify authentication policy weaknesses
```bash
# Get authentication policy configuration
roadrecon authenticationmethods

# Check security defaults
roadrecon securitydefaults

# Find users with legacy authentication enabled
roadrecon users --filter "signInSessionsValidFromDateTime eq null"
```

### Method 6: Advanced Enumeration with Filters

**Step 1:** Custom OData filtering
```bash
# Users created in last 30 days
roadrecon users --filter "createdDateTime gt 2024-11-28"

# Users with LastSignIn within 7 days
roadrecon users --filter "signInDateTime gt 2024-12-21"

# Service principals with certificate credentials
roadrecon serviceprincipals --filter "keyCredentials/any(x: x/type eq 'AsymmetricX509Cert')"

# Applications with reply URLs containing "localhost"
roadrecon applications --filter "replyUrls/any(x: x eq 'http://localhost')"
```

**Step 2:** Search for sensitive data
```bash
# Find applications with sensitive names
roadrecon applications -f "startswith(displayName, 'Service')"

# Users with specific email domains
roadrecon users --filter "mail eq null or mail eq ''"

# Service accounts (common naming pattern)
roadrecon users --filter "startswith(displayName, 'svc')"
```

### Method 7: Token Storage and Persistent Access

**Step 1:** Manage token storage
```bash
# List stored tokens
roadtools tokens --list

# Use specific token
roadrecon users --token ~/.roadtools_auth

# Export token for reuse
roadtools tokens --export token.json

# Import stored credentials for reuse
roadtools tokens --import token.json
```

**Step 2:** Establish persistent enumeration
```bash
# Store credentials securely for repeated access
roadtools credentials --save --username user@example.com

# Use stored credentials in subsequent queries
roadrecon users --auth ~/.roadtools_auth
roadrecon applications --auth ~/.roadtools_auth
roadrecon roles --auth ~/.roadtools_auth
```

### Method 8: Data Export and Analysis

**Step 1:** Export comprehensive enumeration data
```bash
# Export all users to CSV
roadrecon users --csv users.csv --select "displayName,userPrincipalName,mail,accountEnabled"

# Export all applications
roadrecon applications --csv apps.csv

# Export service principals
roadrecon serviceprincipals --json sps.json

# Batch export multiple data sources
for resource in users groups applications roles; do
  roadrecon $resource --json ${resource}.json
done
```

**Step 2:** Parse and analyze exported data
```bash
# Parse JSON and identify risky configurations
python3 << 'EOF'
import json

with open('applications.json', 'r') as f:
    apps = json.load(f)['value']

risky_apps = [app for app in apps if any(
    perm in str(app.get('requiredResourceAccess', []))
    for perm in ['Directory.ReadWrite.All', 'Mail.ReadWrite.All']
)]

print(f"Found {len(risky_apps)} applications with dangerous permissions")
for app in risky_apps:
    print(f"  - {app['displayName']} ({app['appId']})")
EOF
```

---

## Technical Deep Dive

### ROADtools Architecture

**Authentication Flow:**
1. Device Code Grant (no password required)
2. Token obtained via Microsoft Graph
3. Token stored locally in encrypted format
4. Subsequent queries use cached token

**Entra ID Endpoints Queried:**
- `https://graph.microsoft.com/v1.0/` (Microsoft Graph API)
- `https://graph.microsoft.com/beta/` (beta endpoints for extended data)
- `https://management.azure.com/` (Azure ARM API)

### Key API Endpoints Used

| Endpoint | Data Retrieved | Risk Level |
|----------|----------------|-----------|
| `/users` | User accounts and properties | Medium |
| `/applications` | Registered apps and permissions | High |
| `/servicePrincipals` | Service principals | Critical |
| `/directoryRoles` | Admin roles and members | Critical |
| `/conditionalAccessPolicies` | CA rules (may reveal security gaps) | High |
| `/managedIdentities` | Managed identities and roles | High |

---

## Detection Strategies (Blue Team)

### ROADtools Detection

1. **Graph API Pattern Recognition**
   - Rapid enumeration of `/users`, `/applications`, `/servicePrincipals`
   - OData filter patterns typical of automated scanning
   - Unusual user-agent strings or bulk read patterns

2. **Sign-in and Audit Logging**
   ```
   Monitor for:
   - Non-standard Graph API access patterns
   - Service principal creation/credential exposure
   - User enumeration via interactive authentication
   ```

3. **Azure Activity Logging**
   ```
   Alert on:
   - List operations on sensitive resources
   - Multiple API queries from single user/app
   - Off-peak API activity
   ```

### SIEM Detection Rules

```kusto
AuditLogs
| where OperationName in ("Get service principal", "List applications", "List users")
| summarize Count = count() by InitiatedBy, bin(TimeGenerated, 1m)
| where Count > 50
```

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Stealthy Enumeration**
   - Use low-privilege user account (harder to detect than service principal)
   - Space API queries across multiple days
   - Use legitimate OData filters to blend with normal traffic

2. **Token Management**
   - Store tokens in encrypted format
   - Use multiple authentication methods to distribute load
   - Avoid repeated logins from same IP/location

3. **Data Exfiltration**
   - Export data in compressed format
   - Delete local logs and temporary files
   - Use secondary channels for data extraction

### Defensive Measures

1. **Execution Monitoring**
   - Monitor for roadrecon, road, and ROADtools process execution
   - Alert on unusual Python script execution
   - Track Graph API module imports

2. **API Rate Limiting**
   - Implement Conditional Access to throttle bulk queries
   - Alert on Graph API spike patterns
   - Enforce user authentication validation

---

## Mitigation Strategies

1. **Immediate Actions**
   - Review and scope down application permissions
   - Audit service principal assignments
   - Remove unused applications and service principals

2. **Detection & Response**
   - Enable Azure AD Sign-in Logs
   - Monitor Graph API audit trails
   - Alert on bulk enumeration patterns

3. **Long-term Security**
   - Implement Conditional Access policies
   - Use Azure AD Identity Protection
   - Regular RBAC and permission audits

---

## References & Further Reading

- [ROADtools GitHub Repository](https://github.com/dirkjanm/roadtools)
- [Microsoft Graph API Documentation](https://learn.microsoft.com/en-us/graph/overview)
- [Azure AD Audit Logs](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-audit-logs)
- [OData Query Syntax Reference](https://docs.microsoft.com/en-us/odata/concepts/queryoptions/overview)

---

## Related SERVTEP Techniques

- **REC-CLOUD-001**: BloodHound (privilege path visualization)
- **REC-CLOUD-003**: Stormspotter (privilege escalation visualization)
- **REC-CLOUD-004**: AADInternals (complementary Entra ID enumeration)
- **REC-M365-001**: Microsoft Graph API enumeration

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| Installation | 2-5 minutes | Easy |
| Authentication | 1-2 minutes | Easy |
| User enumeration | 1-3 minutes | Easy |
| App/SP enumeration | 2-5 minutes | Easy |
| Full reconnaissance | 5-15 minutes | Easy |
| Data analysis | 10+ minutes | Medium |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
