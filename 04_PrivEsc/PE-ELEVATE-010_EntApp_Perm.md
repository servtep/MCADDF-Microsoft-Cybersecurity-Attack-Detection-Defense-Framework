# [PE-ELEVATE-010]: Enterprise Application Permission (Consent Grant Abuse)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-010 |
| **MITRE ATT&CK v18.1** | [Abuse Elevation Control Mechanism (T1548)](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** If "User Consent" is enabled (default in older tenants), regular users can grant applications permissions to access their data (e.g., `Mail.Read`). However, if an attacker creates a multi-tenant app and tricks an Admin into consenting, the app receives tokens with Admin privileges. Furthermore, if an admin grants "Admin Consent" to an app requiring high privileges (e.g., `Directory.ReadWrite.All`), the Service Principal of that app effectively becomes a Domain Admin.
- **Attack Surface:** Consent Phishing / Illicit Consent Grant.
- **Business Impact:** **Data Exfiltration & Persistence**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Ability to create an App (or trick an admin).
- **Tools:**
    - [365-Stealer](https://github.com/AlteredSecurity/365-Stealer)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Create App**
Register a multi-tenant app requesting `RoleManagement.ReadWrite.Directory`.

**Step 2: Phish Admin**
Send a link: `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=...&scope=RoleManagement.ReadWrite.Directory`

**Step 3: Admin Consents**
If the admin clicks "Accept", the app gets a token.
*Escalation:* The app SP can now promote the attacker to GA.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `Consent to application` | "ConsentContext.IsAdminConsent" = True for unknown applications. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Disable User Consent:** Set "Users can consent to apps accessing company data" to **No**.
*   **Admin Consent Workflow:** Enable the Admin Consent Workflow so users request approval instead of just being blocked or allowed.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-003]
> **Next Logical Step:** [PE-ACCTMGMT-001]
