# [CA-KERB-014]: UnPAC-The-Hash Kerberos Cracking

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-014 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **CVE** | **CVE-2022-33679** (Related downgrade vector) |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** A technique to retrieve the NTLM hash of a user if you possess their TGT (or can request one via PKINIT). The KDC includes the user's NTLM hash in the PAC of the Service Ticket when U2U (User-to-User) authentication is requested. This allows an attacker to "UnPAC" the hash from the ticket structure.
- **Attack Surface:** Kerberos U2U and PKINIT.
- **Business Impact:** **Credential Disclosure**. Turning a TGT (which expires) into an NTLM hash (which is persistent).

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Ability to request a TGT (e.g., via Certificate or known password).
- **Tools:**
    - [Kekeo](https://github.com/gentilkiwi/kekeo)
    - [Rubeus](https://github.com/GhostPack/Rubeus)
    - [Certipy](https://github.com/ly4k/Certipy)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Request TGT via PKINIT**
Authenticate using a certificate.
```bash
certipy auth -pfx user.pfx -domain target.local
```

**Step 2: UnPAC (Automatic in Certipy/Rubeus)**
The tool requests a Service Ticket to *itself* (S4U2Self) or uses U2U. The KDC signs the PAC with the user's NTLM hash. The tool decrypts the PAC (using the session key from Step 1) and extracts the hash.
*Output: `NT Hash: <HASH>`*

**Step 3: Exploitation (CVE-2022-33679 - Downgrade)**
If the user has no pre-auth, force RC4 downgrade to break the session key and decrypt the ticket.
```bash
# Using POC scripts for CVE-2022-33679
python3 cve-2022-33679.py target.local/User
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4769 | Ticket Options `0x08` (ENC-TKT-IN-SKEY) indicating U2U. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Patching:** Apply updates for CVE-2022-33679.
*   **Credential Guard:** Is effectively the only mitigation against local extraction, but network-based extraction (Certipy) is architectural.
*   **Smart Card Required:** Randomizes the NTLM hash on rotation.

## 7. ATTACK CHAIN
> **Preceding Technique:** [REC-CERT-001]
> **Next Logical Step:** [LAT-AD-001]
