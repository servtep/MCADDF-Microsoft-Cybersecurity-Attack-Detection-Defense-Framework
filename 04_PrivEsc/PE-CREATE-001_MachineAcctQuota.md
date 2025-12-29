# [PE-CREATE-001]: Insecure ms-DS-MachineAccountQuota

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-CREATE-001 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The `ms-DS-MachineAccountQuota` (MAQ) attribute in Active Directory determines how many computer accounts a user can create in the domain. By default, this value is set to **10**. This default setting allows any authenticated user (even a low-privileged one) to introduce up to 10 fully functional computer objects into the domain. These attacker-controlled computer accounts have Service Principal Names (SPNs), enabling them to be used in advanced Kerberos attacks such as **Resource-Based Constrained Delegation (RBCD)** and **noPac (SamAccountName Spoofing)**.
- **Attack Surface:** Default Domain Configuration.
- **Business Impact:** **Enabler for Domain Compromise**. While not a direct exploit itself, it is a critical prerequisite for many privilege escalation chains.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Any Authenticated User.
- **Tools:**
    - [StandIn](https://github.com/FuzzySecurity/StandIn)
    - [Powermad](https://github.com/Kevin-Robertson/Powermad)
    - AD PowerShell Module

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Quota**
Verify the current MAQ value.
```powershell
Get-DomainObject "DC=domain,DC=local" | Select-Object ms-DS-MachineAccountQuota
```

**Step 2: Create Machine Account**
Use a tool to create a new machine account.
```powershell
# Using Powermad
New-MachineAccount -MachineAccount "AttackerPC" -Domain "domain.local" -DomainController "DC01"
```
*Result: You now have the credentials for `AttackerPC$`.*

**Step 3: Leverage for Attacks**
*   **RBCD:** Use `AttackerPC$` as the "trusted" principal when configuring delegation on a target server (requires `GenericWrite` on target).
*   **noPac:** Rename `AttackerPC$` to `DC01` (spoofing) to obtain a TGT (requires MAQ > 0 to create the initial account).

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 4741 | Computer Account Created. Filter where `SubjectUserName` is NOT a Domain Admin or a known workstation join account. |
| **Directory Service** | 5136 | Object Created. Class: `computer`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Set to 0:** Change the `ms-DS-MachineAccountQuota` attribute on the Domain Naming Context to **0**.
    ```powershell
    Set-ADDomain -Identity domain.local -Replace @{"ms-DS-MachineAccountQuota"="0"}
    ```
*   **Delegated Joining:** If users need to join workstations, delegate the "Create Computer Objects" permission to a specific group on a specific OU, rather than relying on the domain-wide quota.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-001]
> **Next Logical Step:** [PE-TOKEN-002] (RBCD)
