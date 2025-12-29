# [PE-VALID-009]: SCCM NAA Privilege Escalation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-009 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Domain Accounts (T1078.002)](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Credential Access |
| **Platforms** | Windows AD / SCCM |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The Network Access Account (NAA) is used by SCCM clients to access Distribution Points (DPs) when they cannot use their computer account (e.g., during OSD or workgroup operations). The credentials for the NAA are encrypted and stored in SCCM Policy files on *every* SCCM client. If an attacker gains admin access to *any* client (or compromises the DP), they can extract and decrypt the NAA credentials. Historically, admins configured NAAs as Domain Admins out of laziness.
- **Attack Surface:** SCCM Client Policy (`NetworkAccessAccount` XML).
- **Business Impact:** **Domain Compromise**. If NAA is highly privileged.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Local Admin on an SCCM Client.
- **Tools:**
    - [SCCM-Hunter](https://github.com/GarrettFoster/SCCM-Hunter)
    - [SharpSCCM](https://github.com/Mayyhem/SharpSCCM)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Extract Policy (Local Admin)**
Read the NAA credentials from WMI or Disk using DPAPI.
```bash
SharpSCCM.exe local naa
```

**Step 2: Decrypt**
The tool decrypts the password using the machine's DPAPI key.
*Output: `DOMAIN\NAA_User : Password123`*

**Step 3: Abuse**
If the NAA is a Domain Admin, game over.

## 5. DETECTION (Blue Team Operations)

#### 5.1 SCCM / AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4624 | Logon by the NAA account on workstations where it shouldn't be interactively logging in. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Deprecate NAA:** Switch to **Enhanced HTTP** or **E-HTTP** with computer certificates, removing the need for a generic NAA.
*   **Restrict NAA:** If NAA is required, ensure it has NO privileges other than Read Access to the DP content share. It should never be Domain Admin.

## 7. ATTACK CHAIN
> **Preceding Technique:** [LAT-CLASSIC-001]
> **Next Logical Step:** [CA-UNSC-001]
