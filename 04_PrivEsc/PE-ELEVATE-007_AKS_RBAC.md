# [PE-ELEVATE-007]: AKS RBAC Excessive Permissions (Azure RBAC for K8s)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-007 |
| **MITRE ATT&CK v18.1** | [Abuse Elevation Control Mechanism (T1548)](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | AKS / Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** AKS can be configured to use **Azure RBAC** for authorization instead of native Kubernetes RBAC. In this model, the Azure Role `Azure Kubernetes Service RBAC Admin` maps to `cluster-admin`. However, lesser roles like `Azure Kubernetes Service RBAC Writer` still grant broad permissions. Often, developers are granted `Contributor` on the AKS resource (to manage scaling), which implicitly includes `Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action`. This action allows downloading the *local* admin kubeconfig, bypassing Entra ID RBAC entirely.
- **Attack Surface:** Azure RBAC on AKS Resource.
- **Business Impact:** **Bypassing Identity Controls**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Contributor on AKS Cluster Resource.
- **Tools:**
    - Azure CLI

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Permissions**
Check if you have `listClusterAdminCredential`.
```bash
az role assignment list --assignee <MyID>
```

**Step 2: Dump Admin Config**
Download the non-RBAC admin credential (Local Cluster Admin).
```bash
az aks get-credentials --resource-group <RG> --name <ClusterName> --admin
```

**Step 3: Access**
Use the downloaded kubeconfig.
```bash
kubectl get nodes
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure Activity Logs
| Source | Event | Filter Logic |
|---|---|---|
| **ContainerService** | `List Cluster Admin Credential` | An explicit call to get the local admin kubeconfig. This is suspicious for normal users. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Disable Local Accounts:** Use the `--disable-local-accounts` flag when creating AKS clusters to prevent `listClusterAdminCredential` from working.
*   **Custom Roles:** Do not assign `Contributor` to devs. Use `Azure Kubernetes Service RBAC Cluster User`.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-003]
> **Next Logical Step:** [PE-EXPLOIT-004]
