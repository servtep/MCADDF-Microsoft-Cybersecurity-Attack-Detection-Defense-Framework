# [PE-VALID-013]: Azure Guest User Escalation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-013 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** By default, Guest users in Entra ID have limited permissions. However, if the setting "Guest users have the same access as members" is enabled (older tenants), Guests can enumerate all users and groups. Furthermore, if a Guest is invited to a Group that has been assigned an Entra ID Role (e.g., "Helpdesk Admin"), they inherit that role. Often, admins forget that Guests can be added to privileged groups just like members.
- **Attack Surface:** Guest Permissions.
- **Business Impact:** **Reconnaissance & Escalation**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Guest Access.
- **Tools:**
    - Azure Portal / PowerShell

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Enum**
Check if you can list users.
```powershell
Get-AzureADUser
```

**Step 2: Invite Other Guests**
If the "Guests can invite" setting is enabled (default), invite another attacker account to bypass conditional access or MFA gaps.

**Step 3: Abuse Group Membership**
Check if your Guest user is in any sensitive groups (e.g., "All-Admins").

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `Invite user` | Invitations sent *by* a Guest user. |
| **AuditLogs** | `Add member to group` | Adding a Guest (`UserType: Guest`) to a privileged role-assignable group. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Restrict Guests:** Set "Guest user access" to "Service access is restricted to their own directory objects".
*   **Invitation Rights:** Set "Guest invite settings" so that "Only users assigned to specific admin roles can invite guest users".

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005]
> **Next Logical Step:** [PE-VALID-010]
