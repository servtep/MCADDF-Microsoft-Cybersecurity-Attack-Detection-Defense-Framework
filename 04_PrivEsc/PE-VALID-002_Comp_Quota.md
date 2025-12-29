# [PE-VALID-002]: Computer Account Quota Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-002 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Domain Accounts (T1078.002)](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **CVE** | **CVE-2021-42278** (Related) |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** By default, Active Directory allows any authenticated user to create up to 10 computer accounts (controlled by `ms-DS-MachineAccountQuota`). Attackers can abuse this to create "fake" computer accounts. These accounts are fully functional AD principals with their own SPNs. They can be used for **RBCD attacks** (see PE-TOKEN-002), **noPac** (PE-TOKEN-006), or simply to query AD with a different identity to bypass user-based detections.
- **Attack Surface:** Default Domain Configuration.
- **Business Impact:** **Enabling Pre-Auth RCE**. Required prerequisite for many modern AD exploits.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Any Authenticated User.
- **Tools:**
    - [StandIn](https://github.com/FuzzySecurity/StandIn)
    - [Powermad](https://github.com/Kevin-Robertson/Powermad)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Quota**
```powershell
Get-DomainObject "DC=domain,DC=local" | Select-Object ms-DS-MachineAccountQuota
```

**Step 2: Create Machine**
```powershell
New-MachineAccount -MachineAccount "AttackerPC"
```

**Step 3: Abuse**
Use the credentials (`AttackerPC$`) to perform Kerberoasting, RBCD, or S4U attacks.

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4741 | Computer Account Created. Alert if `SubjectUserName` is a standard user (not an Admin or Workstation Join account). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Set MAQ to 0:** Change `ms-DS-MachineAccountQuota` to **0**.
*   **Process:** Require all computer provisioning to go through a dedicated service account or process.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-001]
> **Next Logical Step:** [PE-TOKEN-002] (RBCD)
