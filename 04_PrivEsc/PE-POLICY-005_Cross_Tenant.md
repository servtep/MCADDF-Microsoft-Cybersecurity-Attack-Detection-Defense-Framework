# [PE-POLICY-005]: Cross-tenant Privilege Escalation (CTS Abuse)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-005 |
| **MITRE ATT&CK v18.1** | [Domain Trust Discovery (T1484.002)](https://attack.mitre.org/techniques/T1484/002/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | M365 / Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure "Cross-Tenant Synchronization" (CTS) allows automated provisioning of users from a "Source" tenant to a "Target" tenant. An attacker who compromises the Source Tenant (e.g., a subsidiary or partner) can modify the CTS configuration to push a new, attacker-controlled account into the Target Tenant. If the Target Tenant has "Inbound Trust" configured to automatically redeem invitations and grant access, this creates a stealthy backdoor.
- **Attack Surface:** Cross-Tenant Access Settings.
- **Business Impact:** **Cross-Tenant Pivot**. Using a dev/test tenant to compromise prod.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Hybrid Identity Administrator (in Source Tenant).
- **Tools:**
    - Azure Portal

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Configure CTS (Source)**
Enable "Cross-Tenant Synchronization" in the Source Tenant's Enterprise Application.

**Step 2: Modify Scope**
Add an attacker-controlled user to the synchronization scope (App Manifest or Group).

**Step 3: Push**
Force a sync job. The user is created in the Target Tenant (Member/Guest).
*If automatic redemption is on, no email is sent.*

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `Add user` | User creation where the "Actor" is the Cross-Tenant Sync Service Principal. |
| **CrossTenantAccess** | `Update policy` | Changes to `inboundTrust` or `synchronization` settings. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Inbound Restrictions:** In the Target Tenant, restrict Cross-Tenant Access to specific Tenant IDs only (Allow-list). Block "All Users" from external tenants.
*   **Review Sync:** Regularly audit the "Cross-Tenant Access Policy" for unexpected inbound trusts.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [LAT-CLOUD-001]
