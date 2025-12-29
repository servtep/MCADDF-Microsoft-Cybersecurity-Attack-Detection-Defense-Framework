# [PE-VALID-007]: Abusing Print Operators Group

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-007 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Domain Accounts (T1078.002)](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Members of the `Print Operators` group have the privilege `SeLoadDriverPrivilege` on Domain Controllers. While they cannot normally write to `C:\Windows\System32\Drivers`, they can manage printers. By using the printer management API to load a malicious driver (BYOVD or custom) from a user-writable location (or exploiting a race condition), they can execute code in the kernel.
- **Attack Surface:** Print Spooler Service.
- **Business Impact:** **Domain Compromise**. Kernel execution on DC.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Member of `Print Operators`.
- **Tools:**
    - [EoPLoadDriver](https://github.com/TarlogicSecurity/EoPLoadDriver)
    - [Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Verify Privilege**
```cmd
whoami /groups | findstr "Print Operators"
whoami /priv | findstr "SeLoadDriverPrivilege"
```

**Step 2: Exploit**
Use a tool to enable the privilege and load a vulnerable driver (e.g., Capcom).
```cmd
EoPLoadDriver.exe System\CurrentControlSet\MyService C:\Temp\Capcom.sys
```

**Step 3: Escalate**
Exploit the driver to get SYSTEM shell.

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **System** | 7045 | Service Installed. Filter for kernel drivers (`Type: Kernel Mode Driver`) installed by non-system accounts. |
| **Security** | 4672 | Privilege Assigned to New Logon. Alert if `SeLoadDriverPrivilege` is assigned to a user session (not `system` or `dwm`). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Restrict Group:** Remove all users from `Print Operators`.
*   **Driver Blocklist:** Enable Microsoft Vulnerable Driver Blocklist (HVCI).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-004]
> **Next Logical Step:** [CA-UNSC-001]
