# [PE-VALID-017]: Azure Lighthouse Cross-Tenant Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-017 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation / Lateral Movement |
| **Platforms** | Entra ID (Cross-Tenant) |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** This is the operational side of [PE-POLICY-004]. Once an attacker has added themselves to a group in the MSP tenant that is authorized via Lighthouse to manage a Customer tenant, they can simply use the Azure Portal or CLI to switch contexts. Unlike B2B Guest access, Lighthouse users are *authenticated in their home tenant* but authorized in the target. This often bypasses Conditional Access policies enforced in the Customer tenant (unless "Require MFA for guest access" is strictly configured for Service Providers).
- **Attack Surface:** Azure Portal "Directory Switcher".
- **Business Impact:** **Invisible Admin Access**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Member of MSP delegation group.
- **Tools:**
    - Azure Portal / CLI

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: List Delegated Resources**
```bash
az login
az managed-services assignment list
```

**Step 2: Switch Context**
No re-authentication is needed if the token is valid for the MSP tenant.
```bash
az account list --all
az account set --subscription <CustomerSubscriptionID>
```

**Step 3: Execute**
Deploy a VM or create a user in the customer subscription.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure Activity Logs (Customer)
| Source | Event | Filter Logic |
|---|---|---|
| **ActivityLog** | `Any` | Look for operations where `Claims.homeTenantId` is NOT the Customer Tenant ID. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **MFA Enforcement:** In the Customer Tenant, ensure Conditional Access policies target "Service Providers" (External Users) and enforce MFA/Device Compliance.
*   **Just-In-Time:** Force MSPs to use PIM for groups (Eligible assignments) rather than Permanent assignments.

## 7. ATTACK CHAIN
> **Preceding Technique:** [PE-POLICY-004]
> **Next Logical Step:** [CA-UNSC-007]
