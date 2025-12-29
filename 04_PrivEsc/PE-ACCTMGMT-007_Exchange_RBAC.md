# [PE-ACCTMGMT-007]: Exchange RBAC Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-007 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Exchange Online |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Exchange Online uses a Role Based Access Control (RBAC) model separate from Entra ID Roles. A user with `Role Management` rights (in Exchange) can create a new "Management Role" that aggregates powerful cmdlets (like `New-ManagementRoleAssignment`, `ApplicationImpersonation`, `Set-Mailbox`). They can then assign this custom role to a standard user or a Service Principal. This is a common persistence mechanism because these roles are not visible in the standard Entra ID "Roles and Administrators" view.
- **Attack Surface:** Exchange Management Shell.
- **Business Impact:** **Stealthy Persistence**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Exchange Administrator / Organization Management.
- **Tools:**
    - PowerShell (ExchangeOnlineManagement)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Create Role**
Create a role based on "Mail Recipients" but add extra capabilities.
```powershell
New-ManagementRole -Name "Helpdesk-Plus" -Parent "Mail Recipients"
```

**Step 2: Add Cmdlets**
Add `ApplicationImpersonation` to the role (if parent structure allows, or create a composite role).

**Step 3: Assign**
Assign to a backdoor user.
```powershell
New-ManagementRoleAssignment -Role "Helpdesk-Plus" -User "lowpriv@domain.com"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Exchange Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Exchange Audit** | `New-ManagementRoleAssignment` | Assigning roles to unexpected users. |
| **Exchange Audit** | `New-ManagementRole` | Creation of custom roles. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Audit Assignments:** Regularly run `Get-ManagementRoleAssignment` to check for users with `ApplicationImpersonation` or `Organization Management` who are not in the corresponding Entra ID roles.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [PE-ACCTMGMT-002]
