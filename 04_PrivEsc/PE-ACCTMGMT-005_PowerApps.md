# [PE-ACCTMGMT-005]: PowerApps / Power Platform Escalation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-005 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Power Platform |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Power Platform Environments often contain "Connections" (e.g., to SQL, SharePoint, Azure). If a user is made an **Environment Admin** (or System Administrator in Dataverse), they can access *all* apps and flows in that environment. They can modify an existing Flow created by a high-privilege user (e.g., a Global Admin who created a flow to manage users) to perform malicious actions. Since the "Connection" is already authenticated by the GA, the modified flow runs with the GA's privileges.
- **Attack Surface:** Power Automate Flows / Connections.
- **Business Impact:** **Impersonation**. Using existing admin connections.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Power Platform Environment Admin.
- **Tools:**
    - Power Automate Portal / CLI

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Discover Flows**
List flows in the environment.
```powershell
Get-AdminFlow
```

**Step 2: Take Ownership**
Assign yourself as owner of a flow owned by a GA.
```powershell
Set-AdminFlowOwnerRole -FlowName <ID> -PrincipalObjectId <MyID> -RoleName CanEdit
```

**Step 3: Modify & Trigger**
Edit the flow to add a "Create User" or "HTTP Request" step. Since the flow uses the GA's connection reference, it executes as them.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Power Platform Logs
| Source | Event | Filter Logic |
|---|---|---|
| **PowerAutomate** | `EditFlow` | Modification of a flow by a user who is not the original creator. |
| **PowerAutomate** | `SetFlowOwner` | Changing ownership of a flow. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Service Principals:** Use Service Principals for production flows rather than user accounts.
*   **DLP Policies:** Configure Data Loss Prevention (DLP) policies to restrict which connectors can be used together.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [PE-VALID-011]
