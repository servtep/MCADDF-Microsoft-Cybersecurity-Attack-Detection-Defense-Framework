# [PE-ACCTMGMT-016]: Microsoft SCIM Provisioning Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-016 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Entra ID (Enterprise Apps) |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** SCIM (System for Cross-domain Identity Management) allows third-party apps (e.g., Workday, Salesforce) to automatically create/update users in Entra ID. This is controlled by a "Provisioning" Service Principal. If an attacker compromises the API Token used for SCIM (often static and long-lived), they can send malicious SCIM requests to Entra ID to create users, update profiles, or add users to groups (if supported), effectively injecting rogue accounts from "Trusted" sources.
- **Attack Surface:** SCIM API Endpoints.
- **Business Impact:** **User Injection**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Compromised App Credential or SCIM Token.
- **Tools:**
    - Postman / `curl`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Obtain Token**
Extract the SCIM Secret Token from the third-party application configuration or a compromised admin's session.

**Step 2: Send SCIM Request**
Send a POST request to the Entra ID SCIM endpoint (`https://graph.microsoft.com/...`) to create a user.
```json
POST /scim/Users
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "backdoor@domain.com",
  "active": true,
  "password": "Password123!"
}
```

**Step 3: Update Group**
If the app has group writeback, add the user to "Helpdesk Admins".

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Provisioning** | `Create User` | Creation events where the "Initiator" is the Service Principal of a connected app (e.g., "Workday to AD User Provisioning"). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Rotate Tokens:** Regularly rotate Secret Tokens used for SCIM provisioning.
*   **Scope Provisioning:** Limit provisioning to specific user attributes. Do not allow apps to modify sensitive groups unless necessary.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [PE-VALID-011]
