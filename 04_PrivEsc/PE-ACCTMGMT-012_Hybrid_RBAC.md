# [PE-ACCTMGMT-012]: Hybrid RBAC / PIM Role Activation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-012 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Hybrid AD / Entra ID |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Organizations often sync on-premises AD users to Entra ID and assign them Cloud Roles (e.g., "Global Administrator" via PIM Eligibility). If an attacker compromises the on-prem AD account of a synced user who is "Eligible" for Global Admin, they can sync the password (PHS) or use Passthrough Authentication (PTA) to log in to the cloud portal and activate the PIM role. Essentially, **Tier 0 On-Prem = Tier 0 Cloud** if synced users hold admin roles.
- **Attack Surface:** Synced Identity.
- **Business Impact:** **On-Prem to Cloud Pivot**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Domain Admin (On-Prem) or Account Operator.
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - Browser

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Identify Eligible Users**
Recon Entra ID to find users with PIM eligibility who are Directory Synced (`DirSyncEnabled: True`).

**Step 2: Compromise On-Prem**
Dump the credentials of that user from LSASS or reset their password in Active Directory Users and Computers (ADUC).
```bash
net user target_admin P@ssword123 /domain
```

**Step 3: Pivot to Cloud**
Wait for AAD Connect to sync the password (approx. 2 mins for PHS). Log in to Azure Portal and activate the role via PIM.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `Reset password` | (On-Prem) Password reset sync events followed immediately by PIM activation in Cloud. |
| **PIM** | `Role activation` | Activation by a synced user from an unusual IP. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Cloud-Only Admins:** NEVER assign Global Admin (or other privileged roles) to synced accounts. Use **Cloud-Only** accounts (e.g., `admin@tenant.onmicrosoft.com`) for all administrative tasks.
*   **Auth Policy:** Enforce Phishing-Resistant MFA (FIDO2) for PIM Activation, which an on-prem attacker cannot easily bypass without the physical key.

## 7. ATTACK CHAIN
> **Preceding Technique:** [PE-VALID-001] (On-Prem Compromise)
> **Next Logical Step:** [PE-ACCTMGMT-011]
