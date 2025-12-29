# [PE-TOKEN-006]: SamAccountName Spoofing (noPac)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-006 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **CVE** | **CVE-2021-42278** & **CVE-2021-42287** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** This attack chains two vulnerabilities.
    1.  **CVE-2021-42278:** Allows a user to rename a machine account (which they created) to have a `sAMAccountName` ending without a `$` (e.g., `DC01`).
    2.  **CVE-2021-42287:** When requesting a Kerberos Service Ticket using S4U2self for a user that *doesn't exist* (because we renamed it back), the KDC falls back to searching for `Name$`.
    **Flow:** Create machine `Attacker$` -> Rename to `DC01` (spoofing DC) -> Request TGT -> Rename back to `Attacker$` -> Request ST using the TGT. The KDC looks for `DC01`, fails, appends `$`, finds `DC01$` (the real DC), and issues a ticket for the Real DC.
- **Attack Surface:** `MachineAccountQuota`.
- **Business Impact:** **Instant Domain Admin**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Any Authenticated User (if MAQ > 0).
- **Tools:**
    - [noPac](https://github.com/Ridter/noPac)
    - [Impacket](https://github.com/fortra/impacket)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Exploit (noPac.py)**
```bash
python3 noPac.py domain.local/user:password -dc-ip 192.168.1.1 -shell
```
*This tool automates the entire create -> rename -> get TGT -> rename -> get ST flow.*

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4741 | Computer Account Created. |
| **Security** | 4781 | The name of an account was changed. Look for removing the `$` from a machine name. |
| **Security** | 4769 | Kerberos Service Ticket Request. Look for `Transited Services` mismatches or S4U2self requests from machine accounts that were recently renamed. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Patch:** Install KB5008380 / KB5008602 (Nov 2021 updates).
*   **MAQ:** Set `MachineAccountQuota` to **0** to prevent users from adding new machines.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-001]
> **Next Logical Step:** [CA-UNSC-001] (DCSync)
