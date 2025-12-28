# [IA-PHISH-003]: OAuth Consent Screen Cloning

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | IA-PHISH-003 |
| **MITRE ATT&CK v18.1** | [Phishing: Spearphishing Link (T1566.002)](https://attack.mitre.org/techniques/T1566/002/) |
| **Tactic** | Initial Access |
| **Platforms** | M365 / Entra ID |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** This technique involves creating a visually identical replica of the legitimate Microsoft OAuth consent screen or login page, often hosted on a lookalike domain. This is distinct from "Consent Phishing" (IA-PHISH-002) because it does *not* use the real Microsoft Identity Provider; instead, it is a traditional credential harvesting site designed to look like an OAuth flow.
- **Attack Surface:** User trust in the UI layout of Microsoft logins. Users trained to look for the "Microsoft" logo may not verify the URL bar.
- **Business Impact:** **Credential Theft** (Username/Password) and potentially MFA token interception if used with a proxy (AiTM).

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** None (External Attacker).
- **Vulnerable Config:** Lack of FIDO2/WebAuthn usage (which binds auth to origin).
- **Tools:**
    - [Evilginx2](https://github.com/kgretzky/evilginx2) (for AiTM)
    - [Gophish](https://github.com/gophish/gophish) (for campaign management)
    - [Modlishka](https://github.com/drk1wi/Modlishka)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Preparation (Infrastructure)**
Register a typo-squatted domain (e.g., `login-microsoft-auth-update.com`) and obtain an SSL certificate (Let's Encrypt).
Configure Evilginx2 with a `phishlet` that targets `login.microsoftonline.com`.

**Step 2: Configuration (Evilginx2)**
```bash
# Inside Evilginx2 console
config domain login-microsoft-auth-update.com
config ip [Attacker_IP]
phishlets hostname microsoft login-microsoft-auth-update.com
phishlets enable microsoft
lures create microsoft
lures get-url 1
```

**Step 3: Exploitation**
Send the generated lure URL to the victim. The user sees a perfect clone of the Microsoft login. When they enter credentials and MFA, Evilginx proxies it to the real site, capturing the session cookie.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Network Indicators
- **Newly Registered Domains (NRDs):** Monitor proxy logs for traffic to domains registered < 24 hours ago.
- **SSL Certificates:** Monitor for new certificates issued for domains containing "microsoft", "login", "office365" not owned by Microsoft.

#### 5.2 Browser/Endpoint Detection
Use **Microsoft Defender for Office 365** Safe Links policies.

#### 5.3 Microsoft Sentinel (KQL) - AiTM Detection
Detects impossible travel or session cookies being used from a different IP shortly after generation (requires high-fidelity sign-in logs).

```kusto
SigninLogs
| where TimeGenerated > ago(1h)
| where RiskDetail == "aiTmThroughPhishing" or RiskEventTypes has "suspiciousBrowser"
| project TimeGenerated, UserPrincipalName, IPAddress, RiskDetail, RiskLevelDuringSignIn
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Endpoint:** Deploy **Windows Defender SmartScreen** and **Network Protection** to block known malicious domains.
*   **Identity:**
    *   **FIDO2 / Windows Hello for Business:** This is the *only* true mitigation for AiTM/Cloning. The FIDO protocol validates the domain (`microsoft.com`) and will refuse to authenticate to the attacker's domain (`login-fake.com`).
    *   **Conditional Access:** Enforce "Compliant Device" requirements. Attackers proxying traffic cannot present the device's Intune compliance certificate.

## 7. ATTACK CHAIN
> **Preceding Technique:** [REC-AD-001] (Tenant Discovery)
> **Next Logical Step:** [IA-VALID-001] (Using stolen credentials to access portal)
