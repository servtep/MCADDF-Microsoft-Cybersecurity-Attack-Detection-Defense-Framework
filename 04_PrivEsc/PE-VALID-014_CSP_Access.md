# [PE-VALID-014]: Microsoft Partners / CSP Access Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-014 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Cloud Accounts (T1078.004)](https://attack.mitre.org/techniques/T1078/004/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | M365 / Entra ID |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Cloud Solution Providers (CSPs) manage customer tenants via Delegated Admin Privileges (DAP) or Granular Delegated Admin Privileges (GDAP). DAP historically granted Global Admin access to the partner's "AdminAgents" group. If an attacker compromises a CSP Partner tenant, they automatically gain Global Admin access to *all* customer tenants managed by that partner.
- **Attack Surface:** Partner Relationships.
- **Business Impact:** **Massive Supply Chain Compromise**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Compromise of a CSP Account.
- **Tools:**
    - [Partner Center PowerShell](https://learn.microsoft.com/en-us/powershell/partnercenter/install)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: List Customers**
From the Partner Tenant:
```powershell
Get-PartnerCustomer
```

**Step 2: Access Customer**
Generate a token for a specific customer tenant.
```powershell
$Token = New-PartnerAccessToken -TenantId <CustomerTenantID> -Scopes "https://graph.microsoft.com/.default"
Connect-MgGraph -AccessToken $Token
```

**Step 3: Create User**
Create a new Global Admin in the customer tenant for persistence.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs (Customer Side)
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Partner Delegation` | Sign-ins where `ResourceTenantId` != `HomeTenantId`. |
| **AuditLogs** | `Add user` | User creation performed by a Service Principal associated with the Partner. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Migrate to GDAP:** Deprecate DAP immediately. Use GDAP to grant time-bound, least-privilege access (e.g., Service Support Admin instead of Global Admin) to partners.
*   **Remove Unused Partners:** Regularly audit "Partner Relationships" in M365 Admin Center and remove old vendors.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PHISH-005] (Compromise CSP)
> **Next Logical Step:** [PE-POLICY-005]
