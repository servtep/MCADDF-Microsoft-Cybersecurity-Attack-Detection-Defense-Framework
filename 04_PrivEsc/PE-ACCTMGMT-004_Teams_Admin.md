# [PE-ACCTMGMT-004]: Teams Admin to Global Admin (Via App Deployment)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-004 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation / Phishing |
| **Platforms** | Microsoft Teams |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Teams Administrators control the apps and tabs available to users. An attacker with this role can upload a custom "LOB" (Line of Business) app—effectively a malicious web page wrapped in a Teams Tab—and pin it to the sidebar of all users, including Global Admins. This app can mimic a login page (to steal creds) or request OAuth permissions (Graph API token theft). Because it appears inside the trusted Teams client, users are highly likely to trust it.
- **Attack Surface:** Teams App Policies.
- **Business Impact:** **Credential Theft**. Targeting C-Suite/Admins.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Teams Administrator.
- **Tools:**
    - Custom Teams App (Manifest.json)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Create Malicious App**
Build a Teams App (zip) that points to an attacker-controlled phishing site or uses `microsoftTeams.authentication` to request tokens.

**Step 2: Upload & Approve**
In Teams Admin Center -> Manage Apps -> Upload.

**Step 3: Pin App**
Teams Admin Center -> Setup Policies -> Global (Org-wide default) -> Add App -> Move to Top.
*Result: The app appears at the top of the sidebar for every user.*

## 5. DETECTION (Blue Team Operations)

#### 5.1 Unified Audit Log
| Source | Event | Filter Logic |
|---|---|---|
| **MicrosoftTeams** | `AppUploaded` | Upload of a custom app. |
| **MicrosoftTeams** | `AppInstalled` | Installation of an app to a team or user scope by an admin. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Restrict Uploads:** Disable "Allow interaction with custom apps" in Global App Setup Policy.
*   **Review Apps:** Regularly audit "Manage Apps" for unknown custom applications.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [IA-PHISH-003]
