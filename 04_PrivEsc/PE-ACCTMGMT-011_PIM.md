# [PE-ACCTMGMT-011]: Privileged Identity Management (PIM) Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-011 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Entra ID PIM allows admins to be "Eligible" for a role rather than holding it permanently. An attacker with `Privileged Role Administrator` (or Global Admin) rights can abuse PIM to maintain stealthy persistence. Instead of assigning a permanent Global Admin role (which triggers alerts), they can assign a compromised user (or a Service Principal) as "Eligible" for Global Admin. This user appears normal until they "Activate" the role. Furthermore, PIM settings can be modified to remove MFA requirements or approval workflows for activation.
- **Attack Surface:** PIM Settings & Assignments.
- **Business Impact:** **Stealthy Persistence**. Evading audits of "Active" admins.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Privileged Role Administrator / Global Admin.
- **Tools:**
    - Azure Portal / PowerShell (`MgGraph`)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Assign Eligibility**
Make a backdoor user eligible for GA without a time limit (Permanent Eligibility).
```powershell
Open-PIMEligibleRole -PrincipalId <BackdoorID> -RoleDefinitionName "Global Administrator"
```

**Step 2: Weaken PIM Policy**
Modify the Role Settings for "Global Administrator" to disable MFA and Approval.
```powershell
Update-MgIdentityGovernancePrivilegedAccessGroupRoleScheduleInstance -MfaRequired $false
```

**Step 3: Activate**
When needed, activate the role.
```bash
az rest --method post --url "/providers/Microsoft.Authorization/roleAssignments/activate..."
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Directory** | `Add member to role` | Look for PIM-specific events: `Add eligible member to role`. |
| **Directory** | `Update role setting` | Changes to PIM Role Settings (e.g., removing MFA requirement). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Audit Eligibility:** Treat "Eligible" admins exactly the same as "Active" admins. Audit them daily.
*   **Alerting:** Alert on *any* modification to PIM Role Settings (`Update role setting`).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [PE-VALID-011]
