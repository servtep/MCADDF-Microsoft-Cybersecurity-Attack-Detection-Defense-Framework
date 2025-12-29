# [PE-POLICY-002]: Creating Rogue GPOs

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-002 |
| **MITRE ATT&CK v18.1** | [Domain Policy Modification: Group Policy Modification (T1484.001)](https://attack.mitre.org/techniques/T1484/001/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Instead of modifying an existing GPO (which might be monitored), an attacker with `Create Group Policy Object` rights can create a *new* GPO, configure malicious settings (e.g., adding a local admin user), and link it to an Organizational Unit (OU) where they have `gPLink` permissions. This is often less noisy than modifying a core policy like "Default Domain Policy".
- **Attack Surface:** OUs and GPO Container.
- **Business Impact:** **Stealthy Persistence**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Create GPO + Link GPO rights on target OU.
- **Tools:**
    - [Powermad](https://github.com/Kevin-Robertson/Powermad)
    - PowerShell (GroupPolicy Module)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Create GPO**
```powershell
New-GPO -Name "DefenderUpdates" -Comment "Critical Updates"
```

**Step 2: Configure Malicious Settings**
(e.g., using `Set-GPPrefRegistryValue` or SharpGPOAbuse on the new GPO).

**Step 3: Link to OU**
```powershell
New-GPLink -Name "DefenderUpdates" -Target "OU=Workstations,DC=domain,DC=local"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 5137 | A directory service object was created. Object Class: `groupPolicyContainer`. |
| **Security** | 5136 | Link change. Attribute `gPLink` modified on an OU object. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Restrict Creation:** Remove "Create Group Policy Objects" right from non-admin users (often found in `Group Policy Creator Owners` group).
*   **OU Permissions:** Audit who can Link GPOs (`gPLink`) to sensitive OUs.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-002]
> **Next Logical Step:** [LAT-CLASSIC-001]
