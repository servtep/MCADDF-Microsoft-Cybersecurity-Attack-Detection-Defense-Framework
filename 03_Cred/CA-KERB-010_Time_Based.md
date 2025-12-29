# [CA-KERB-010]: Time-Based Kerberos Exploitation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-010 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Exploiting the time skew tolerance of Kerberos (default 5 minutes). Attackers can replay captured TGTs or AS-REQs within this window, or manipulate the local clock to accept expired tickets if the KDC clock is out of sync.
- **Attack Surface:** Kerberos Replay Cache.
- **Business Impact:** **Persistence**. Reusing valid authentication tokens before they expire.

## 3. PREREQUISITES & CONFIGURATION
- **Vulnerable Config:** Default GPO "Maximum tolerance for computer clock synchronization" (5 mins).
- **Tools:**
    - [Rubeus](https://github.com/GhostPack/Rubeus)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Capture Ticket**
Extract a valid TGT from a compromised host.

**Step 2: Replay (Pass-the-Ticket)**
Inject the ticket into a new session. If the ticket is close to renewal or expiration, the attacker can use the renewal window.

```powershell
.\Rubeus.exe renew /ticket:BASE64... /autorenew
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4771 | Kerberos Pre-Auth Failed: `0x25` (KRB_AP_ERR_SKEW) - Clock Skew too great. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **NTP:** Ensure all hosts sync time strictly with the PDC Emulator.
*   **Replay Cache:** The KDC maintains a replay cache (Rcache) to detect identical Authenticators. Ensure this is not disabled.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-DUMP-001]
> **Next Logical Step:** [LAT-AD-001]
