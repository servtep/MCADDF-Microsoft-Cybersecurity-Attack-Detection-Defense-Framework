# [PE-POLICY-004]: Azure Lighthouse Delegation Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-004 |
| **MITRE ATT&CK v18.1** | [Domain Policy Modification (T1484.001)](https://attack.mitre.org/techniques/T1484/001/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Entra ID (Cross-Tenant) |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure Lighthouse allows Service Providers (MSPs) to manage customer subscriptions. This is done via a `registrationDefinition` which defines which *Principal ID* (in the MSP tenant) gets which *Role Definition ID* (in the Customer tenant). If an attacker compromises the MSP tenant and adds themselves to the group associated with the `PrincipalId`, they instantly gain access to the Customer's environment. Alternatively, if the delegation grants `User Access Administrator` to the MSP (rare but possible), the attacker can elevate permissions further within the customer tenant.
- **Attack Surface:** Lighthouse Registration Definitions.
- **Business Impact:** **Supply Chain Compromise**. One compromised MSP affects multiple customers.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Group Administrator (in MSP Tenant).
- **Tools:**
    - Azure Portal

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Identify Lighthouse Groups**
In the MSP tenant, check which groups are used for Lighthouse delegations.
```bash
az managed-services assignment list
```

**Step 2: Add Self to Group**
Add the attacker user to the "MSP Admins" group.

**Step 3: Access Customer**
Switch directories in Azure Portal to the customer tenant and manage resources.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Activity Logs (Customer Side)
| Source | Event | Filter Logic |
|---|---|---|
| **ActivityLog** | `Write` / `Delete` | Actions performed by users with a `homeTenantId` different from the local tenant ID. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Role Limitations:** Customers should never delegate `Owner` or `User Access Administrator` roles to MSPs via Lighthouse. Stick to `Contributor` or `Reader`.
*   **PIM for Lighthouse:** MSPs should enable PIM on the groups used for Lighthouse, requiring Just-In-Time elevation even for their own staff.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005] (Compromise MSP)
> **Next Logical Step:** [PE-POLICY-005]
