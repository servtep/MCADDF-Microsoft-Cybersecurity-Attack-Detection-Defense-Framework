# REC-CLOUD-003: Stormspotter Privilege Escalation Visualization

**SERVTEP ID:** REC-CLOUD-003  
**Technique Name:** Stormspotter privilege escalation visualization  
**MITRE ATT&CK Mapping:** T1087.004 (Account Discovery - Cloud Account)  
**CVE Reference:** N/A  
**Environment:** Entra ID / Azure  
**Severity:** High  
**Difficulty:** Medium  

---

## Executive Summary

Stormspotter is an Azure security testing tool that creates an interactive visualization of cloud environments and their privilege escalation paths. Unlike BloodHound which focuses on graph relationships, Stormspotter maps Azure subscriptions, management groups, resource groups, and RBAC relationships in a three-dimensional interactive interface. The tool enables attackers to identify privilege escalation chains across Azure subscriptions and management groups that would be difficult to spot through manual enumeration.

---

## Objective

Visualize Azure privilege escalation paths to identify:
- Subscription and management group hierarchies
- Cross-subscription privilege escalation routes
- RBAC permission delegation chains
- Resource group access paths
- Managed identity escalation chains
- Service principal privilege inheritance
- Azure Lighthouse delegation paths
- Custom role escalation opportunities

---

## Prerequisites

- Stormspotter GitHub repository
- Python 3.7+ with pip
- Azure CLI and authentication
- Node.js 12+ (for visualization frontend)
- Web browser for interactive analysis
- Azure subscription with Owner/Reader role minimum

---

## Execution Procedures

### Method 1: Installation and Setup

**Step 1:** Download and install Stormspotter
```bash
# Clone repository
git clone https://github.com/Azure/Stormspotter
cd Stormspotter

# Install Python dependencies
pip install -r requirements.txt

# Install Node.js frontend dependencies
cd frontend
npm install
cd ..
```

**Step 2:** Authenticate to Azure
```bash
# Login with Azure CLI
az login

# Verify authentication
az account show
```

### Method 2: Data Collection

**Step 1:** Run Stormspotter collection
```bash
# Collect Azure subscription data
python3 stormspotter.py --collect

# Specify particular subscription
python3 stormspotter.py --collect --subscription {subscription-id}

# Collect from all accessible subscriptions
python3 stormspotter.py --collect --all-subscriptions

# Save to specific output directory
python3 stormspotter.py --collect --output /path/to/data/
```

**Step 2:** Collection options and filters
```bash
# Collect specific resource types
python3 stormspotter.py --collect --resource-types "Microsoft.Compute/virtualMachines" \
  "Microsoft.Storage/storageAccounts"

# Limit scope to management group
python3 stormspotter.py --collect --management-group {mg-id}

# Verbose output for debugging
python3 stormspotter.py --collect --verbose
```

### Method 3: Visualization and Analysis

**Step 1:** Start Stormspotter visualization server
```bash
# Start backend API server
python3 stormspotter.py --serve

# Server accessible at: http://localhost:8000

# Custom port
python3 stormspotter.py --serve --port 9000
```

**Step 2:** Access visualization interface
```
1. Open browser to http://localhost:8000
2. Load collected data
3. Interact with 3D environment
4. Explore subscription hierarchies
5. Examine RBAC relationships
```

**Step 3:** Navigate privilege escalation paths
```
UI Navigation:
- Select subscription/management group
- View resource groups and resources
- Click on RBAC assignments
- Examine user/service principal roles
- Identify escalation routes
```

### Method 4: Advanced Analysis with Cypher-like Queries

**Step 1:** Query privilege escalation paths
```bash
# Find all paths to Owner role within subscription
python3 -c "
from stormspotter import Storm
storm = Storm.load('data/')

# Find users with Owner access
owners = [user for user in storm.users 
          if 'Owner' in user.roles]

# Find service principals with Contributor+ roles
dangerous_sps = [sp for sp in storm.service_principals 
                 if any(role in ['Contributor', 'Owner'] for role in sp.roles)]
"
```

**Step 2:** Identify cross-subscription escalation
```bash
# Query management group hierarchy
python3 << 'EOF'
from stormspotter import Storm
storm = Storm.load('data/')

# Find management groups with weak RBAC
for mg in storm.management_groups:
    print(f"Management Group: {mg.name}")
    print(f"  Users with admin roles: {len(mg.admin_users)}")
    print(f"  Service principals: {len(mg.service_principals)}")
    
    # Identify escalation paths
    for user in mg.admin_users:
        print(f"    - {user.name} ({user.roles})")
EOF
```

### Method 5: Export and Report Generation

**Step 1:** Export visualization data
```bash
# Export to JSON format
python3 stormspotter.py --export --format json --output report.json

# Export to CSV
python3 stormspotter.py --export --format csv --output report/

# Export specific findings
python3 stormspotter.py --export --filter "role:Owner" --output owners.csv
```

**Step 2:** Generate privilege escalation report
```python
#!/usr/bin/env python3
from stormspotter import Storm
import json

storm = Storm.load('data/')

report = {
    "subscription_count": len(storm.subscriptions),
    "user_count": len(storm.users),
    "admin_users": [u.name for u in storm.users if 'Owner' in u.roles],
    "dangerous_service_principals": [
        {"name": sp.name, "roles": sp.roles} 
        for sp in storm.service_principals 
        if any(r in sp.roles for r in ['Contributor', 'Owner'])
    ],
    "management_groups": [
        {"name": mg.name, "admin_count": len(mg.admin_users)}
        for mg in storm.management_groups
    ]
}

with open('privilege_escalation_report.json', 'w') as f:
    json.dump(report, f, indent=2)
```

### Method 6: Identifying Specific Escalation Chains

**Step 1:** Find Owner role escalation paths
```bash
# All users/SPs with Owner role
python3 << 'EOF'
from stormspotter import Storm

storm = Storm.load('data/')

print("=== OWNER ROLE HOLDERS ===")
for sp in storm.service_principals:
    if 'Owner' in sp.roles:
        print(f"Service Principal: {sp.name}")
        print(f"  App ID: {sp.app_id}")
        print(f"  Subscription: {sp.subscription}")
        print()
EOF
```

**Step 2:** Identify Lighthouse delegations
```bash
# Find Azure Lighthouse delegations (high-risk escalation vector)
python3 << 'EOF'
from stormspotter import Storm

storm = Storm.load('data/')

print("=== AZURE LIGHTHOUSE DELEGATIONS ===")
for delegation in storm.lighthouse_delegations:
    print(f"Delegated by: {delegation.delegating_tenant}")
    print(f"Delegated to: {delegation.delegated_tenant}")
    print(f"Scope: {delegation.scope}")
    print(f"Role: {delegation.role}")
    print()
EOF
```

**Step 3:** Map managed identity privilege escalation
```bash
# Find managed identities with dangerous roles
python3 << 'EOF'
from stormspotter import Storm

storm = Storm.load('data/')

print("=== MANAGED IDENTITY ESCALATION ===")
for mi in storm.managed_identities:
    if any(role in ['Owner', 'Contributor'] for role in mi.roles):
        print(f"MI: {mi.name}")
        print(f"  Attached to: {mi.attached_resources}")
        print(f"  Roles: {mi.roles}")
        print()
EOF
```

---

## Technical Deep Dive

### Stormspotter Data Model

**Collected Objects:**
- Subscriptions
- Management Groups
- Resource Groups
- Resources (VMs, Storage, etc.)
- Users and Service Principals
- Role Assignments (RBAC)
- Custom Roles
- Managed Identities

**Relationship Mapping:**
- User → Subscription (RBAC)
- Service Principal → Resource (RBAC)
- Management Group → Subscription (inheritance)
- Managed Identity → Role (attachment)
- Lighthouse Delegation → Tenant (delegation)

### Visualization Features

1. **3D Environment:** Spatial representation of Azure hierarchy
2. **Network Graph:** Relationship visualization
3. **Interactive Filtering:** Focus on specific escalation paths
4. **Role Analysis:** Visual RBAC permission display

---

## Detection Strategies (Blue Team)

### Stormspotter Detection

1. **API Activity Pattern**
   - Bulk enumeration of subscriptions, management groups
   - Repeated requests to `/subscriptions` and `/providers` endpoints
   - Enumeration of role assignments across scopes

2. **Azure Activity Logging**
   ```
   Monitor for:
   - ListRole operations
   - Get role assignment queries
   - Bulk read operations across subscriptions
   ```

3. **Authentication Logging**
   - Service principal with unexpected Graph API access
   - User authentication from unusual locations
   - MFA bypass or conditional access evasion

---

## Operational Security (OpSec) Considerations

### Attacker Perspective

1. **Credential Management**
   - Use low-privileged service principal
   - Avoid service principal from same tenant (if possible)
   - Distribute API calls across time

2. **Data Exfiltration**
   - Compress and encrypt visualization data
   - Export findings in aggregated format
   - Delete local Stormspotter artifacts

### Defensive Measures

1. **API Rate Limiting**
   - Throttle subscription enumeration queries
   - Alert on bulk role assignment reads
   - Implement Conditional Access policies

2. **Monitoring & Detection**
   - Alert on service principal with unexpected scopes
   - Monitor Azure Activity Log for pattern anomalies
   - Track role assignment query spikes

---

## Mitigation Strategies

1. **Immediate Actions**
   - Review and remove unnecessary Owner role assignments
   - Audit management group delegations
   - Disable unused service principals

2. **Detection & Response**
   - Enable Azure Activity Log monitoring
   - Implement RBAC least-privilege principle
   - Regular subscription and role audits

3. **Long-term Security**
   - Use Privileged Identity Management (PIM)
   - Implement management group governance
   - Deploy Azure Policy for RBAC enforcement

---

## References & Further Reading

- [Stormspotter GitHub Repository](https://github.com/Azure/Stormspotter)
- [Azure RBAC Documentation](https://learn.microsoft.com/en-us/azure/role-based-access-control/)
- [Azure Management Groups](https://learn.microsoft.com/en-us/azure/governance/management-groups/)
- [Azure Lighthouse Security](https://learn.microsoft.com/en-us/azure/lighthouse/concepts/security-baseline)

---

## Related SERVTEP Techniques

- **REC-CLOUD-001**: BloodHound (AD privilege analysis)
- **REC-CLOUD-002**: ROADtools (Entra ID enumeration)
- **PE-POLICY-003**: Azure Management Group Escalation
- **PE-VALID-010**: Azure Role Assignment Abuse

---

## Timeline

| Phase | Duration | Difficulty |
|-------|----------|------------|
| Setup & auth | 5-10 minutes | Easy |
| Data collection | 5-30 minutes | Easy |
| Visualization startup | 2-5 minutes | Easy |
| Analysis | 15+ minutes | Medium |
| **Total** | **30-50 minutes** | **Medium** |

---

**Last Updated:** December 2025  
**Classification:** SERVTEP Research Division  
**Status:** Verified & Operational
