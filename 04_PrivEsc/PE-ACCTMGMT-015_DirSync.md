# [PE-ACCTMGMT-015]: Directory Synchronization Manipulation (Hard Match Abuse)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-015 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Hybrid AD |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Azure AD Connect matches on-prem users to cloud users using a "Source Anchor" (usually `ms-DS-ConsistencyGuid` or `objectGuid`). If an attacker creates a user on-prem and manually sets its `ConsistencyGuid` to match the `ImmutableId` of an existing Cloud-Only Global Admin, AAD Connect may "Hard Match" (merge) the two accounts during the next sync cycle. This allows the attacker to overwrite the cloud admin's password with the on-prem password, effectively taking over the cloud account.
- **Attack Surface:** AD Attributes (`ms-DS-ConsistencyGuid`).
- **Business Impact:** **Cloud Account Takeover**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Domain Admin / Account Operator (On-Prem).
- **Tools:**
    - `AADInternals`
    - `Set-ADUser`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Get Target ImmutableId**
Retrieve the ImmutableId of the target Cloud Admin (requires reading Azure AD).
```powershell
Get-AzureADUser -ObjectId "cloudadmin@tenant.com" | Select ImmutableId
```

**Step 2: Create On-Prem User**
Create a standard user in AD.

**Step 3: Set ConsistencyGuid**
Convert the Cloud ImmutableId (Base64) to Hex and set it on the on-prem user.
```powershell
Set-ADUser -Identity "new_user" -Replace @{ "ms-DS-ConsistencyGuid" = [System.Convert]::FromBase64String("ImmutableID_Here") }
```

**Step 4: Sync**
Wait for AAD Connect. The cloud user is now linked to the on-prem user. Resetting the on-prem password now resets the cloud password.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Directory Service** | `Sync` | A Cloud-Only user being converted to "Directory Synced" (Source: Windows Server AD). |
| **AuditLogs** | `Update user` | Changes to `ImmutableId` or `DirSyncEnabled`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Block Hard Match:** Microsoft has enabled "BlockSoftMatch" by default for admins, but "Hard Match" (ImmutableId match) may still work if not explicitly blocked.
*   **Cloud-Only Admins:** Cloud Admins should *never* have an ImmutableId set. Audit for any admin with a non-null ImmutableId.

## 7. ATTACK CHAIN
> **Preceding Technique:** [PE-VALID-001]
> **Next Logical Step:** [PE-ACCTMGMT-014]
