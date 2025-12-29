# [PE-ELEVATE-008]: SaaS Admin Account Escalation (ServiceNow/Salesforce SSO)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-008 |
| **MITRE ATT&CK v18.1** | [Abuse Elevation Control Mechanism (T1548)](https://attack.mitre.org/techniques/T1548/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Entra ID / SaaS |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Many SaaS apps (ServiceNow, Salesforce, AWS SSO) integrated with Entra ID use **Provisioning** to sync roles. These roles are mapped from Entra ID Groups or User Attributes. If an attacker can modify the user attribute that maps to the SaaS admin role (e.g., `department` = "IT-Admins" or a custom `extensionAttribute`), they can elevate their privileges in the target SaaS platform without touching the target's internal user database.
- **Attack Surface:** Entra ID Provisioning & SSO Claims.
- **Business Impact:** **Cross-System Escalation**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Administrator / Helpdesk Admin (in Entra ID).
- **Tools:**
    - Azure Portal

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Analyze SSO Config**
Check the Enterprise App's "Single Sign-On" -> "Attributes & Claims" section. Look for logic like:
`Role` = `user.assignedRoles` OR `Role` = `user.department`.

**Step 2: Modify Attribute**
If mapped to `department`, change your user's department to "Admins".
```powershell
Update-MgUser -UserId <MyID> -Department "SysAdmins"
```

**Step 3: Login to SaaS**
Initiate SSO. The SAML assertion will contain the new attribute, elevating access in Salesforce/ServiceNow.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `Update user` | Changes to sensitive attributes like `Department`, `JobTitle`, or `ExtensionAttributes`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Use App Roles:** Do not map SaaS roles to mutable user attributes like Department. Map them to **App Roles** (`appRoles`) which require explicit assignment by an App Admin.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [PE-VALID-011]
