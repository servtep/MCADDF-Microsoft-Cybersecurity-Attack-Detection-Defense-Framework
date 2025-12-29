# [PE-POLICY-007]: Azure Policy Definition Injection

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-007 |
| **MITRE ATT&CK v18.1** | [Domain Policy Modification (T1484.001)](https://attack.mitre.org/techniques/T1484/001/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Entra ID / Azure |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure Policies are used to enforce compliance (e.g., "VMs must have Tag X"). However, Policies can also have **Remediation Tasks** (`deployIfNotExists`) that run with a **Managed Identity** assigned to the Policy Assignment. This Managed Identity often has high privileges (Contributor/Owner) to fix non-compliant resources. An attacker with `Microsoft.Authorization/policyDefinitions/write` can modify an existing Policy Definition to execute malicious deployments (e.g., creating a user, adding a role assignment) using the Policy's high-privileged identity, effectively escalating their own rights.
- **Attack Surface:** Custom Policy Definitions.
- **Business Impact:** **Stealthy Escalation**. Leveraging a "Compliance" tool for attacks.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** `Resource Policy Contributor` (or custom role with `policyDefinitions/write`).
- **Tools:**
    - Azure CLI / Portal

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Identify Policy Identity**
Find a Policy Assignment that uses a Managed Identity with high privileges.
```bash
az policy assignment list --query "[].{Name:name, Identity:identity.principalId}"
```

**Step 2: Modify Definition**
Update the linked Policy Definition's `deployment` template to run a malicious ARM template (e.g., adding the attacker to the "Owner" role).

**Step 3: Trigger Remediation**
Manually trigger a remediation task.
```bash
az policy remediation create --policy-assignment <ID>
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure Activity Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Policy** | `Write PolicyDefinition` | Modification of policy rules, especially `deployIfNotExists` content. |
| **Directory** | `RoleAssignment` | New role assignments created by a "Policy" Managed Identity (check Actor). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Least Privilege:** Ensure Policy Managed Identities only have the granular permissions needed for the specific remediation task, not generic `Contributor`.
*   **Code Review:** Treat Policy Definitions as Infrastructure-as-Code (IaC) and require Pull Request reviews for changes.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [PE-POLICY-003]
