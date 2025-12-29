# [PE-VALID-015]: AKS Node Identity Compromise

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-015 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | AKS / Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** In AKS, each node is a VM that uses a **System-Assigned Managed Identity** (Node Identity) to pull container images from ACR. However, AKS also creates a user-assigned identity (Kubelet Identity) used for cluster operations. If an attacker escapes a pod to the underlying node (see PE-EXPLOIT-004), they can access the Managed Identity endpoint on that node. This identity often has `AcrPull` rights but may be over-privileged to `Contributor` on the Node Resource Group, allowing the attacker to modify other resources like Load Balancers or Virtual Networks.
- **Attack Surface:** AKS Nodes.
- **Business Impact:** **Cluster & Network Compromise**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Root on an AKS Node (Container Escape).
- **Tools:** `curl`, `az cli`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Get Token**
On the node:
```bash
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H 'Metadata: true'
```

**Step 2: Attack ACR**
Use the token to pull malicious images or push to the registry (if `AcrPush` is present).

**Step 3: Modify Network**
If the identity is `Contributor` on the MC_ resource group, create a Public IP and expose internal services.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure Activity Logs
| Source | Event | Filter Logic |
|---|---|---|
| **ContainerRegistry** | `Pull` / `Push` | Anomalous image access patterns from AKS Node IPs. |
| **Network** | `Write PublicIP` | Creation of public IPs by the AKS Service Principal outside of standard scaling events. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Least Privilege:** Ensure the Kubelet Identity only has `AcrPull` and `Network Contributor` (scoped strictly to the VNet).
*   **Pod Identity:** Use **Entra Workload ID** (Pod Identity) to assign specific identities to Pods, rather than relying on the Node's broad identity.

## 7. ATTACK CHAIN
> **Preceding Technique:** [PE-EXPLOIT-004]
> **Next Logical Step:** [PE-VALID-011]
