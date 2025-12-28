# REC-CLOUD-005: Azure Resource Graph Enumeration

**SERVTEP ID:** REC-CLOUD-005  
**Technique Name:** Azure Resource Graph enumeration  
**MITRE ATT&CK Mapping:** T1580 (Cloud Service Discovery)  
**CVE Reference:** N/A  
**Environment:** Entra ID / Azure  
**Severity:** High  
**Difficulty:** Medium  

---

## Executive Summary

Azure Resource Graph is a powerful query service that enables comprehensive enumeration of Azure resources across subscriptions and management groups. Unlike Azure CLI or SDK calls that require subscription-level access, Resource Graph provides cross-subscription querying with a single authenticated session. Attackers use Resource Graph queries to discover VMs, storage accounts, databases, and other critical infrastructure—enabling infrastructure mapping, vulnerability assessment prioritization, and lateral movement planning.

---

## Objective

Enumerate Azure infrastructure across subscriptions to identify:
- Virtual machines and their configurations
- Storage accounts and data repositories
- SQL databases and other data services
- Managed identities and their permissions
- Network security groups and firewall rules
- Key vaults and credential stores
- Application gateways and load balancers
- Resource owner information and RBAC assignments
- Resource health and patch status

---

## Prerequisites

- Azure subscription access (Reader role minimum)
- Azure CLI installed and configured
- PowerShell 5.0+ with Az.ResourceGraph module
- Kusto Query Language (KQL) knowledge (optional)
- Internet connectivity to Azure Resource Graph API

---

## Execution Procedures

### Method 1: Azure CLI Resource Graph Queries

**Step 1:** Basic resource enumeration
```bash
# Login to Azure
az login

# List all resources across subscriptions
az graph query -q "resources | project name, type, resourceGroup"

# Get resource count by type
az graph query -q "resources | summarize count() by type"

# Find all VMs
az graph query -q "resources | where type == 'microsoft.compute/virtualmachines'"
```

**Step 2:** Advanced VM enumeration
```bash
# Get all VMs with their network configuration
az graph query -q "
  resources 
  | where type == 'microsoft.compute/virtualmachines'
  | project name, resourceGroup, location, 
            vmSize=properties.hardwareProfile.vmSize,
            osType=properties.storageProfile.osDisk.osType"

# Find VMs with public IPs
az graph query -q "
  resources 
  | where type == 'microsoft.compute/virtualmachines'
  | join (resources | where type == 'microsoft.network/publicIPAddresses') on id
  | project vmName=name, publicIP=properties.ipAddress"

# Get VMs by owner/creator
az graph query -q "
  resources 
  | where type == 'microsoft.compute/virtualmachines'
  | project name, resourceGroup, createdBy=tags.CreatedBy, owner=tags.Owner"
```

**Step 3:** Storage account discovery
```bash
# List all storage accounts
az graph query -q "
  resources 
  | where type == 'microsoft.storage/storageaccounts'
  | project name, resourceGroup, kind, sku=properties.sku.name"

# Find storage accounts with public access
az graph query -q "
  resources 
  | where type == 'microsoft.storage/storageaccounts'
  | where properties.publicNetworkAccess == 'Enabled'"

# Get storage accounts by region
az graph query -q "
  resources 
  | where type == 'microsoft.storage/storageaccounts'
  | summarize count() by location"
```

### Method 2: PowerShell Azure Resource Graph Queries

**Step 1:** Install and authenticate
```powershell
# Install Azure ResourceGraph module
Install-Module -Name Az.ResourceGraph -Force

# Authenticate to Azure
Connect-AzAccount

# Get all subscriptions (if cross-subscription access needed)
Get-AzSubscription
```

**Step 2:** Execute KQL queries via PowerShell
```powershell
# Search all resources
$query = @"
resources 
| project name, type, resourceGroup, subscriptionId
| limit 100
"@

Search-AzGraph -Query $query

# Find resources by type
$vmQuery = @"
resources 
| where type == 'microsoft.compute/virtualmachines'
| project name, resourceGroup, vmSize=properties.hardwareProfile.vmSize
"@

$vms = Search-AzGraph -Query $vmQuery
$vms | ConvertTo-Json | Out-File vms.json
```

**Step 3:** Comprehensive infrastructure mapping
```powershell
# Get all resources with their tags
$resourceQuery = @"
resources 
| project name, type, resourceGroup, tags, subscriptionId
| order by type asc
"@

$allResources = Search-AzGraph -Query $resourceQuery
$allResources | Export-Csv all_resources.csv -NoTypeInformation

# Export by resource type
$resourceTypes = $allResources | Group-Object type

foreach ($type in $resourceTypes) {
  $filename = ($type.Name -replace '[/\\:*?"<>|]', '_') + '.csv'
  $type.Group | Export-Csv $filename -NoTypeInformation
}
```

### Method 3: Sensitive Resource Discovery

**Step 1:** Find database servers
```bash
# Query SQL servers
az graph query -q "
  resources 
  | where type == 'microsoft.sql/servers'
  | project name, resourceGroup, fullyQualifiedDomainName=properties.fullyQualifiedDomainName"

# Find CosmosDB instances
az graph query -q "
  resources 
  | where type == 'microsoft.documentdb/databaseaccounts'
  | project name, kind=kind, documentEndpoint=properties.documentEndpoint"

# Get all databases
az graph query -q "
  resources 
  | where type == 'microsoft.sql/servers/databases'
  | project name, resourceGroup, serverName=split(id, '/')[8]"
```

**Step 2:** Key vaults and secrets (partial enumeration)
```bash
# Find all Key Vaults
az graph query -q "
  resources 
  | where type == 'microsoft.keyvault/vaults'
  | project name, resourceGroup, location, 
            uri=properties.vaultUri,
            enablePurgeProtection=properties.enablePurgeProtection"

# Identify vaults with public access
az graph query -q "
  resources 
  | where type == 'microsoft.keyvault/vaults'
  | where properties.publicNetworkAccess != 'Disabled'"
```

**Step 3:** Managed identities enumeration
```bash
# Find all managed identities
az graph query -q "
  resources 
  | where type == 'microsoft.managedidentity/userassignedidentities'
  | project name, resourceGroup, clientId=properties.clientId"

# Get system-assigned identities (via VMs)
az graph query -q "
  resources 
  | where type == 'microsoft.compute/virtualmachines'
  | where identity.type contains 'SystemAssigned'
  | project vmName=name, principalId=identity.principalId"
```

### Method 4: Network and Security Discovery

**Step 1:** Network security groups and rules
```bash
# Find all NSGs
az graph query -q "
  resources 
  | where type == 'microsoft.network/networksecuritygroups'
  | project name, resourceGroup, location"

# Find NSGs allowing broad access (0.0.0.0/0)
az graph query -q "
  resources 
  | where type == 'microsoft.network/networksecuritygroups/securityrules'
  | where properties.sourceAddressPrefix contains '0.0.0.0'
  | project name, resourceGroup, direction=properties.direction, access=properties.access"
```

**Step 2:** Application gateways and load balancers
```bash
# Find all application gateways
az graph query -q "
  resources 
  | where type == 'microsoft.network/applicationgateways'
  | project name, resourceGroup, backendPools=properties.backendAddressPools"

# Find load balancers
az graph query -q "
  resources 
  | where type == 'microsoft.network/loadbalancers'
  | project name, resourceGroup, frontendPorts=properties.frontendIPConfigurations"
```

### Method 5: Cost Analysis and Resource Enumeration

**Step 1:** Identify expensive or high-value resources
```bash
# Find large VM instances
az graph query -q "
  resources 
  | where type == 'microsoft.compute/virtualmachines'
  | where properties.hardwareProfile.vmSize contains 'Standard_E' or 
          properties.hardwareProfile.vmSize contains 'Standard_D64'
  | project name, vmSize=properties.hardwareProfile.vmSize, resourceGroup"

# Find resources with high storage
az graph query -q "
  resources 
  | where type == 'microsoft.storage/storageaccounts'
  | where sku.name contains 'Premium'
  | project name, skuTier=sku.tier, location, resourceGroup"
```

**Step 2:** Resource utilization analysis
```bash
# Find unattached disks
az graph query -q "
  resources 
  | where type == 'microsoft.compute/disks'
  | where managedBy == ''
  | project name, sizeGB=properties.diskSizeGB, resourceGroup"

# Identify unused network interfaces
az graph query -q "
  resources 
  | where type == 'microsoft.network/networkinterfaces'
  | where properties.virtualMachine == null
  | project name, resourceGroup, location"
```

### Method 6: Cross-Subscription Infrastructure Mapping

**Step 1:** Multi-subscription queries (with proper permissions)
```powershell
# Query across all accessible subscriptions
$allSubsQuery = @"
resources 
| where subscriptionId in ('sub-id-1', 'sub-id-2', 'sub-id-3')
| project name, type, subscriptionId, resourceGroup, location
| summarize count() by subscriptionId, type
"@

Search-AzGraph -Query $allSubsQuery

# Export infrastructure across subscriptions
$crossSubQuery = @"
resources 
| where subscriptionId in (~SUBSCRIPTION_IDS~)
| project name, type, resourceGroup, subscriptionId, location, tags
"@

$crossSubQuery = $crossSubQuery -replace '~SUBSCRIPTION_IDS~', 
  ($subscriptions | ForEach-Object {"'$($_.id)'"} | Join-String -Separator ',')

$results = Search-AzGraph -Query $crossSubQuery
$results | Export-Csv infrastructure_mapping.csv -NoTypeInformation
```

**Step 2:** Identify resource ownership across subscriptions
```powershell
# Find all resources with owner tags
$ownerQuery = @"
resources 
| where tags contains 'Owner' or tags contains 'owner'
| project name, owner=tags.Owner, department=tags.Department, 
          resourceGroup, subscriptionId, type
"@

$ownerResources = Search-AzGraph -Query $ownerQuery
$ownerResources | Group-Object owner | 
  ForEach-Object {
    Write-Host "Owner: $($_.Name) - Resources: $($_.Count)"
    $_.Group | Export-Csv "owner_$($_.Name).csv" -NoTypeInformation
  }
```

---

## Technical Deep Dive

### Azure Resource Graph Query Language

**Basic Query Structure:**
```kql
resources
| where type == 'microsoft.compute/virtualmachines'
| project name, resourceGroup, vmSize=properties.hardwareProfile.vmSize
| limit 100
```

**Common Operators:**
- `where` - Filter resources by condition
- `project` - Select specific properties
- `summarize` - Aggregate data
- `join` - Combine multiple queries
- `order by` - Sort results
- `limit` - Restrict result count

### Resource Types and Discovery

| Resource Type | API Endpoint | Sensitivity |
|---|---|---|
| microsoft.compute/virtualmachines | VM configuration | High |
| microsoft.storage/storageaccounts | Storage access | Critical |
| microsoft.sql/servers | Database access | Critical |
| microsoft.keyvault/vaults | Secrets/keys | Critical |
| microsoft.managedidentity/* | Service identity | High |
| microsoft.network/* | Network topology | High |

---

## Detection Strategies (Blue Team)

### Resource Graph Query Monitoring

1. **Azure Activity Logging**
   - Monitor `Microsoft.ResourceGraph/resources/read` operations
   - Alert on bulk query patterns
   - Track cross-subscription queries

2. **Query Pattern Analysis**
   - Excessive `where` filters targeting sensitive data
   - Large result set queries (summarize with high cardinality)
   - Resource enumeration across subscriptions

3. **Authentication Logging**
   - Service principal with unexpected ResourceGraph permissions
   - Non-interactive authentication for resource enumeration
   - Off-peak query activity

### SIEM Detection Rules

```kusto
AzureActivity
| where OperationName == "Read resource groups"
  or OperationName == "Get resources"
| summarize QueryCount = count() by CallerIpAddress, Caller, bin(TimeGenerated, 5m)
| where QueryCount > 50
```

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Query Stealth**
   - Use broad resource enumeration (appear as normal reporting)
   - Space queries across time
   - Use filter conditions to avoid result-set visibility

2. **Credential Management**
   - Use service principal with Reader role (common for legitimate tools)
   - Avoid custom roles that stand out
   - Distribute queries across multiple accounts

### Defensive Measures

1. **RBAC Enforcement**
   - Limit Resource Graph access to authorized personnel
   - Use Privileged Identity Management (PIM) for elevated queries
   - Audit cross-subscription query permissions

2. **Query Monitoring**
   - Enable diagnostic logging for Resource Graph
   - Alert on large-scale resource enumeration
   - Monitor for sensitive resource queries

---

## Mitigation Strategies

1. **Immediate Actions**
   - Audit Resource Graph access permissions
   - Review service principals with Reader role
   - Restrict cross-subscription query access

2. **Detection & Response**
   - Enable Azure Activity Log monitoring
   - Alert on bulk resource enumeration
   - Monitor for unusual Resource Graph patterns

3. **Long-term Security**
   - Implement Privileged Identity Management (PIM)
   - Use custom RBAC roles with minimal permissions
   - Regular access reviews and cleanup
   - Encrypt sensitive resource properties

---

## References & Further Reading

- [Azure Resource Graph Overview](https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview)
- [Kusto Query Language (KQL) Reference](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- [Azure Resource Graph Query Examples](https://learn.microsoft.com/en-us/azure/governance/resource-graph/samples/starter-query-samples)
- [Azure Activity Log Monitoring](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)

---

## Related SERVTEP Techniques

- **REC-CLOUD-001**: BloodHound (privilege path analysis)
- **REC-CLOUD-002**: ROADtools (Entra ID enumeration)
- **REC-CLOUD-003**: Stormspotter (subscription mapping)
- **REC-M365-001**: Microsoft Graph API enumeration
- **PE-POLICY-003**: Azure Management Group Escalation

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| Authentication | 1-2 minutes | Easy |
| Basic enumeration | 2-5 minutes | Easy |
| Advanced queries | 5-15 minutes | Medium |
| Cross-subscription | 5-20 minutes | Medium |
| Full assessment | 20-40 minutes | Medium |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
