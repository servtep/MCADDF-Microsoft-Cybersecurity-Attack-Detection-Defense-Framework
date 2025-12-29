# [PE-ACCTMGMT-002]: Exchange Online Admin to Global Admin (Via Mailbox Access)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-002 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | M365 / Exchange Online |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Exchange Administrators have the right to grant themselves access to *any* user's mailbox, including Global Administrators. While they cannot reset a Global Admin's password directly (due to role tiering restrictions in M365), they can read the emails. If a Global Admin has ever emailed a password, received a "Password Reset" link, or stored 2FA backup codes in their mailbox, the Exchange Admin can harvest these credentials to take over the GA account.
- **Attack Surface:** User Mailboxes.
- **Business Impact:** **Sensitive Data Exposure & Elevation**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Exchange Administrator.
- **Tools:**
    - PowerShell (ExchangeOnlineManagement)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Grant Access**
Give yourself "Full Access" to the target GA's mailbox.
```powershell
Add-MailboxPermission -Identity "admin@domain.com" -User "attacker@domain.com" -AccessRights FullAccess -InheritanceType All
```

**Step 2: Search Mailbox**
Search for keywords like "password", "login", "reset", "secret".
```powershell
# Using eDiscovery (Compliance Admin) or opening in Outlook Web App
```

**Step 3: Trigger Reset**
Trigger a password reset for a service the GA uses, knowing the link will arrive in the mailbox you now control.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Exchange Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Exchange Audit** | `Add-MailboxPermission` | A user granting themselves `FullAccess` to a privileged account. |
| **Exchange Audit** | `MailItemsAccessed` | (Requires E5) Access to specific mail items by a delegate user. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **PIM:** Require PIM for Exchange Admin role.
*   **Separation:** Do not use Global Admin accounts for email. GA accounts should be cloud-only and *licenseless* (no mailbox), preventing this specific vector.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [IA-PASS-001]
