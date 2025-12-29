# [PE-ACCTMGMT-009]: Microsoft Defender for Cloud (Logic App) Escalation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-009 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Azure / Logic Apps |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Microsoft Defender for Cloud uses "Workflow Automation" (Logic Apps) to respond to alerts (e.g., "Block IP", "Isolate Machine"). These Logic Apps use a Managed Identity or an API Connection (authorized by a high-priv user) to perform actions. If a user has `Logic App Contributor` rights on the Resource Group containing these security playbooks, they can edit the Logic App designer. They can modify the workflow to execute arbitrary commands (e.g., via `RunCommand`) or extract the credentials used in the API connections.
- **Attack Surface:** Security Playbooks.
- **Business Impact:** **Security Tool Weaponization**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Logic App Contributor.
- **Tools:**
    - Azure Portal

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Locate Playbooks**
Find Logic Apps linked to Defender for Cloud (often in a "Security" RG).

**Step 2: Edit Workflow**
Open the Logic App Designer. Add a step to:
1.  Read the output of a sensitive step (e.g., KeyVault Secret retrieval).
2.  Send the data to an attacker webhook (RequestBin).
3.  Add a Role Assignment using the Logic App's identity.

**Step 3: Trigger**
Manually trigger the Logic App run.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure Activity Logs
| Source | Event | Filter Logic |
|---|---|---|
| **LogicApp** | `Write Workflow` | Modification of existing security playbooks. |
| **LogicApp** | `Run Workflow` | Manual triggering of playbooks normally triggered by alerts. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Lock Down RG:** The Resource Group containing Security Playbooks should have strict ACLs. Only Security Admins should have Write access.
*   **Monitor Changes:** Alert on any modification to Logic Apps tagged as "Security".

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-003]
> **Next Logical Step:** [PE-VALID-011]
