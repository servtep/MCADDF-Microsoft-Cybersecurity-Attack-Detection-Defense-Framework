# REC-CLOUD-001: BloodHound for Azure/Entra Privilege Paths

**SERVTEP ID:** REC-CLOUD-001  
**Technique Name:** BloodHound for Azure/Entra privilege paths  
**MITRE ATT&CK Mapping:** T1087.004 (Account Discovery - Cloud Account)  
**CVE Reference:** N/A  
**Environment:** Entra ID / Azure  
**Severity:** Critical  
**Difficulty:** Medium  

---

## Executive Summary

BloodHound is a graph-based reconnaissance tool that visualizes Active Directory and Entra ID privilege escalation paths. The Azure/Entra module (AzureHound) extends BloodHound capabilities to cloud environments, revealing privilege escalation chains that would be invisible through manual analysis. By ingesting credentials or tokens from authenticated users, BloodHound maps RBAC relationships, role assignments, and trust chains—enabling attackers to identify paths from user accounts to tenant-wide compromise (Global Administrator or equivalent).

---

## Objective

Map Azure and Entra ID privilege escalation paths to identify:
- Routes to Global Administrator/Tenant Admin roles
- Service principal privilege escalation chains
- Application permission escalation paths
- Management group permission inheritance vulnerabilities
- Cross-subscription privilege escalation
- Entra ID role escalation chains
- Managed identity misconfiguration exploitation

---

## Prerequisites

- BloodHound v4.2+ and Neo4j database
- AzureHound collector (latest version)
- Azure/Entra ID credentials (Owner/Contributor role minimum)
- PowerShell 5.0+ with Az.Accounts module
- Network access to Azure APIs and Entra ID Graph endpoints
- 4GB+ RAM for Neo4j database
- Sufficient storage for large Azure environments (100MB-1GB)

---

## Execution Procedures

### Method 1: Installing BloodHound and AzureHound

**Step 1:** Download and install BloodHound
```bash
# Download BloodHound binary (Linux/Windows/macOS available)
wget https://github.com/BloodHoundAD/BloodHound/releases/download/v4.3.1/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip
cd BloodHound-linux-x64

# Start BloodHound application
./BloodHound

# Default credentials: neo4j / neo4j
# Change password on first login
```

**Step 2:** Install and configure Neo4j database
```bash
# Download Neo4j Community Edition
wget https://dist.neo4j.org/neo4j-community-4.4.11-unix.tar.gz
tar -xzf neo4j-community-4.4.11-unix.tar.gz
cd neo4j-community-4.4.11

# Start Neo4j service
./bin/neo4j start

# Access Neo4j browser: http://localhost:7474
# Default credentials: neo4j / neo4j
```

**Step 3:** Download AzureHound collector
```bash
# Clone AzureHound repository
git clone https://github.com/BloodHoundAD/AzureHound
cd AzureHound
pip install -r requirements.txt

# Alternatively, download compiled binary
wget https://github.com/BloodHoundAD/AzureHound/releases/download/v2.1.0/azurehound-windows-amd64.zip
```

### Method 2: Collecting Azure Data with AzureHound

**Step 1:** Authenticate to Azure
```powershell
# Install Az PowerShell modules
Install-Module -Name Az.Accounts -Force
Install-Module -Name Az.Subscription -Force

# Authenticate with Azure credentials
Connect-AzAccount -Tenant {tenant-id}

# Verify authentication
Get-AzSubscription
```

**Step 2:** Run AzureHound collector
```bash
# Collect Azure enumeration data
./azurehound-windows-amd64.exe -outputdir azdata/ list --tenant {tenant-id}

# Requires credentials:
# Option 1: Interactive login via browser
./azurehound list --tenant {tenant-id}

# Option 2: Service principal authentication
./azurehound list --tenant {tenant-id} \
  --client-id {service-principal-id} \
  --client-secret {service-principal-secret}

# Option 3: Certificate-based authentication
./azurehound list --tenant {tenant-id} \
  --client-id {service-principal-id} \
  --certificate-path /path/to/cert.pfx \
  --certificate-password {password}
```

**Step 3:** Collect Entra ID data
```bash
# Enumerate Entra ID users, groups, applications, roles
./azurehound-windows-amd64.exe --tenant {tenant-id} \
  -p entraIDUsers \
  -p entraIDGroups \
  -p entraIDApplications \
  -p entraIDServicePrincipals \
  -p entraIDRoles \
  -p entraIDAdministrativeUnits

# Export to JSON files (default output)
# Files saved to current directory
```

**Step 4:** Collect subscription and RBAC data
```bash
# Enumerate Azure subscriptions
./azurehound list --tenant {tenant-id} \
  -p subscriptions \
  -p resourceGroups \
  -p virtualMachines \
  -p managedIdentities

# Export Azure RBAC relationships
./azurehound list --tenant {tenant-id} \
  -p roleAssignments \
  -p managementGroups
```

### Method 3: Importing Data into BloodHound

**Step 1:** Upload collected data files
```
1. Open BloodHound web interface (http://localhost:7687)
2. Login with Neo4j credentials
3. Click "Upload Data"
4. Select all JSON files from AzureHound output directory
5. Wait for import to complete (may take 5-30 minutes for large environments)
```

**Step 2:** Verify data import
```
Navigate to "Database Info" to confirm:
- Number of nodes imported
- Number of relationships created
- Azure-specific objects (subscriptions, VMs, roles)
```

### Method 4: Analyzing Privilege Escalation Paths in BloodHound

**Step 1:** Find paths to Global Administrator role
```
BloodHound UI Steps:
1. Open "Queries" panel
2. Select "Azure RBAC" → "Find Shortest Paths to Global Admin"
3. Specify starting user/application
4. Analyze privilege escalation chain
```

**Step 2:** Query privilege escalation paths via Cypher
```cypher
// Find all paths from authenticated user to Global Administrator
MATCH p=shortestPath((u:AzureUser)-[*1..]->(role:AzureRole {name:"Global Administrator"}))
RETURN p

// Find privilege escalation via Application Permissions
MATCH (app:AzureApplication)-[rel:HasRole]->(role:AzureRole)
WHERE role.name CONTAINS "Admin"
RETURN app.name, app.AppId, role.name

// Identify Service Principal to Global Admin paths
MATCH p=shortestPath((sp:AzureServicePrincipal)-[*1..]->(role:AzureRole {name:"Global Administrator"}))
RETURN p

// Find User to Privileged Application paths
MATCH p=shortestPath((user:AzureUser {name:{username}})-[*1..]->(app:AzureApplication {name:{appname}}))
WHERE app.AppPermissions CONTAINS "admin"
RETURN p
```

**Step 3:** Analyze Entra ID role escalation
```cypher
// Find paths to Entra ID Administrator role
MATCH p=shortestPath((u:User)-[*1..]->(r:AzureRole {name:"Entra ID Administrator"}))
RETURN p

// Identify over-privileged service principals
MATCH (sp:AzureServicePrincipal)-[rel:HasRole]->(role:AzureRole)
RETURN sp.name, count(role) as RoleCount
ORDER BY RoleCount DESC
LIMIT 10

// Find unused service principals with admin access
MATCH (sp:AzureServicePrincipal)-[rel:HasRole]->(role:AzureRole)
WHERE sp.lastSignIn < datetime() - duration({days: 90})
RETURN sp.name, role.name
```

**Step 4:** Detect cross-subscription privilege escalation
```cypher
// Find privilege escalation across subscriptions
MATCH (sub1:AzureSubscription)-[rel1]->(user:User),
      (sub2:AzureSubscription)-[rel2]->(role:AzureRole)
WHERE sub1 <> sub2
RETURN sub1.name, sub2.name, user.name, role.name

// Identify management group delegated permissions
MATCH (mg:AzureManagementGroup)-[rel:Manages]->(sub:AzureSubscription)
RETURN mg.name, sub.name, mg.permissions
```

### Method 5: BloodHound Custom Queries and Analysis

**Step 1:** Import custom queries
```powershell
# Custom Cypher queries for Azure-specific analysis
# Save to custom_queries.json in BloodHound queries directory

$customQueries = @{
  "name" = "Custom Azure Queries"
  "queries" = @(
    @{
      "name" = "Find All Global Admins"
      "query" = "MATCH (u:User)-[rel:HasRole]->(r:AzureRole {name:'Global Administrator'}) RETURN u.name, u.mail"
    },
    @{
      "name" = "Service Principals with Dangerous Permissions"
      "query" = "MATCH (sp:AzureServicePrincipal)-[rel:HasPermission]->(perm) WHERE perm CONTAINS 'All' RETURN sp, perm"
    }
  )
}
$customQueries | ConvertTo-Json | Out-File custom_queries.json
```

**Step 2:** Analyze user and application relationships
```cypher
// Find users who are members of privileged applications
MATCH (user:User)-[rel:MemberOf]->(app:AzureApplication)
WHERE app.name CONTAINS "Admin" OR app.name CONTAINS "Privileged"
RETURN user.name, app.name

// Identify applications with overly broad API permissions
MATCH (app:AzureApplication)-[rel:HasPermission]->(perm:Permission)
WHERE perm.name CONTAINS "Directory.ReadWrite.All" OR perm.name CONTAINS "Mail.ReadWrite.All"
RETURN app.name, collect(perm.name) as Permissions

// Find managed identity access paths
MATCH (mi:ManagedIdentity)-[rel:HasRole]->(role:AzureRole)
RETURN mi.name, role.name
```

**Step 3:** Generate exploitation chain report
```cypher
// Generate detailed exploitation path for specific user
MATCH p=shortestPath((user:User {name:"attacker@example.com"})-[*1..5]->(admin:AzureRole {name:"Global Administrator"}))
WITH [node in nodes(p) | node.name] as chain
RETURN chain, length(p) as PathLength
```

### Method 6: Exporting and Reporting Findings

**Step 1:** Export graph data for analysis
```powershell
# Export privileged paths to CSV
$session = New-NeoSession -BaseUri http://localhost:7687 -Credential (New-Object System.Management.Automation.PSCredential("neo4j", (ConvertTo-SecureString "password" -AsPlainText -Force)))

# Query and export
$pathsToAdmin = Invoke-NeoQuery -Session $session -Query "MATCH p=shortestPath((u:User)-[*1..]->(r:AzureRole {name:'Global Administrator'})) RETURN u.name, nodes(p)"
$pathsToAdmin | Export-Csv privilege_paths.csv
```

**Step 2:** Create visual exploitation chains
```
BloodHound Visualization:
1. Right-click on user node
2. Select "Shortest Paths to..." → "Global Administrator"
3. Expand relationship details
4. Document each step for exploitation report
```

---

## Technical Deep Dive

### BloodHound Graph Model

**Node Types in Azure/Entra:**
- AzureUser
- AzureServicePrincipal
- AzureApplication
- AzureRole
- AzureSubscription
- ManagedIdentity
- AzureManagementGroup
- AzureResource

**Relationship Types:**
- HasRole
- MemberOf
- HasPermission
- CanManage
- CanDelegate
- CanReset

### Privilege Escalation Chains

**Type 1: Direct Role Assignment**
```
User → Owner Role → Full Subscription Control
```

**Type 2: Application-based Escalation**
```
User → Reads App Secrets → Service Principal Token → Global Admin Role
```

**Type 3: Managed Identity Leverage**
```
User → Creates VM with Managed Identity → MI has Contributor Role → Resource Compromise
```

---

## Detection Strategies (Blue Team)

### BloodHound Scanner Detection

1. **API Pattern Recognition**
   - Excessive Graph API calls to `/users`, `/servicePrincipals`, `/roleAssignments`
   - Bulk enumeration of directory objects
   - High-frequency permission queries

2. **Authentication Logging**
   ```
   Alert on:
   - Service principal with unexpected Graph API scopes
   - User running PowerShell against Graph API in unusual patterns
   - AzureHound-signature queries (User-Agent, request patterns)
   ```

3. **Azure Activity Logging**
   ```
   Monitor:
   - Read activity on sensitive RBAC operations
   - ListKeys operations for secrets/credentials
   - Service Principal creation/modification
   ```

### SIEM Detection Rules

```kusto
AuditLogs
| where OperationName == "Get user"
| summarize UserCount = dcount(TargetResources), CallCount = count() by CallerIpAddress, InitiatedBy
| where UserCount > 50 and CallCount > 100
| project-reorder CallerIpAddress, UserCount, CallCount
```

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Credential Usage**
   - Use service principal with minimal required permissions
   - Authenticate during off-peak hours
   - Space API calls across multiple hours to avoid rate limiting

2. **Data Exfiltration**
   - Store BloodHound database on isolated system
   - Compress and encrypt exported data
   - Delete local BloodHound artifacts after analysis

### Defensive Measures

1. **Privilege Monitoring**
   - Alert on service principals with Graph API admin scopes
   - Monitor role assignment queries
   - Restrict who can read directory roles

2. **API Rate Limiting**
   - Implement Conditional Access rules limiting graph.microsoft.com queries
   - Set throttling for bulk read operations
   - Alert on Graph API spike patterns

---

## Mitigation Strategies

1. **Immediate Actions**
   - Remove unnecessary Global Administrator role assignments
   - Audit all service principal permissions (scope down)
   - Disable unused service principals

2. **Detection & Response**
   - Enable Azure AD Sign-in Logs
   - Monitor Graph API audit logs
   - Alert on privilege escalation paths

3. **Long-term Security**
   - Implement Privileged Identity Management (PIM)
   - Use Conditional Access to restrict admin access
   - Regular RBAC reviews and cleanup

---

## References & Further Reading

- [BloodHound GitHub Repository](https://github.com/BloodHoundAD/BloodHound)
- [AzureHound Documentation](https://github.com/BloodHoundAD/AzureHound)
- [Microsoft Graph API Documentation](https://learn.microsoft.com/en-us/graph/overview)
- [Azure RBAC Best Practices](https://docs.microsoft.com/en-us/azure/role-based-access-control/best-practices)

---

## Related SERVTEP Techniques

- **REC-CLOUD-002**: ROADtools (alternative Entra enumeration)
- **REC-CLOUD-003**: Stormspotter (PE path visualization)
- **PE-ACCTMGMT-001**: App Registration Privilege Escalation
- **PE-VALID-010**: Azure Role Assignment Abuse

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| Setup (BloodHound + AzureHound) | 10-20 minutes | Medium |
| Data collection | 5-30 minutes | Easy |
| Import into Neo4j | 5-60 minutes | Easy |
| Analysis | 30+ minutes | Medium |
| **Total** | **1-2+ hours** | **Medium** |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
