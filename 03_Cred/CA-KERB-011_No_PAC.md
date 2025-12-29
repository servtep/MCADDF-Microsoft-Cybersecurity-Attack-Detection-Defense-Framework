# [CA-KERB-011]: No-PAC Kerberos Bypass

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-011 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access / Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **CVE** | **CVE-2021-42278** / **CVE-2021-42287** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Exploiting a logical flaw in the KDC where the Privilege Attribute Certificate (PAC) is not correctly validated if the requesting account name is modified. By creating a machine account, requesting a TGT, renaming the machine account to match a Domain Controller (no-PAC), and then requesting a service ticket, an attacker can obtain a TGS as a Domain Controller.
- **Attack Surface:** `sAMAccountName` modification and Kerberos TGS requests.
- **Business Impact:** **Instant Domain Admin**. Elevates a standard user to Domain Admin in minutes.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Standard Domain User (with quota to create 1 machine account).
- **Vulnerable Config:** Unpatched Domain Controllers (pre-Nov 2021).
- **Tools:**
    - [noPac.py (Impacket)](https://github.com/fortra/impacket)
    - [Rubeus](https://github.com/GhostPack/Rubeus)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Automated Exploitation (Linux)**
Use `noPac.py` to scan for vulnerability and exploit.
```bash
# Scan
noPac.py target.local/user:password -scan

# Exploit (Drops into shell as SYSTEM on DC)
noPac.py target.local/user:password -use-ldap-shell
```

**Step 2: Manual Flow (Windows/Rubeus)**
1.  Create machine account `evil$`.
2.  Clear SPNs from `evil$`.
3.  Rename `evil$` to `DC01` (DC name without $).
4.  Request TGT for `DC01`.
5.  Rename `DC01` back to `evil$`.
6.  Request S4U2Self ticket using the TGT from step 4. KDC grants it as the DC.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4741 | Computer Account Created. |
| **Security** | 4781 | The name of an account was changed (`Old: evil$`, `New: DC01`). |
| **Security** | 4769 | TGS Request where requesting account does not match the account in the ticket. |

#### 5.2 Sentinel (KQL)
```kusto
SecurityEvent
| where EventID == 4781
| where TargetUserName !endswith "$" // Renaming to a non-machine name (stealing DC identity)
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Patching:** Install patches for **CVE-2021-42278** & **CVE-2021-42287**.
*   **Hardening:** Set `MachineAccountQuota` to **0** to prevent users from creating the initial machine account required for the exploit.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-VALID-001]
> **Next Logical Step:** [CA-DUMP-002] (DCSync)
