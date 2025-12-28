# [IA-VALID-001]: Default Credential Exploitation

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | IA-VALID-001 |
| **MITRE ATT&CK v18.1** | [Valid Accounts: Default Accounts (T1078.001)](https://attack.mitre.org/techniques/T1078/001/) |
| **Tactic** | Initial Access |
| **Platforms** | Windows AD / Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Exploiting accounts that are deployed with known default passwords or predictable initial credential patterns. In Hybrid environments, this often targets **Azure AD Connect** SQL accounts, third-party integrated applications, or mass-created user accounts with "Welcome" passwords.
- **Attack Surface:** Login Portals, LDAP, SMB, and SQL Instances.
- **Business Impact:** **Instant Access**. Gaining a foothold as a valid user without triggering exploit alarms.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** None (Unauthenticated).
- **Vulnerable Config:**
    - Admins setting predictable initial passwords (e.g., `Welcome123!`, `Company2025!`).
    - Infrastructure software (Printers, iLO, Backup Agents) joined to AD with default credentials.
- **Tools:**
    - [Kerbrute](https://github.com/ropnop/kerbrute)
    - [Spray](https://github.com/0xZDH/Spray)
    - Hydr

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Preparation (User Enumeration)**
Acquire a list of valid usernames via OSINT or enumeration (REC-AD-002).

**Step 2: Exploitation (Smart Password Spraying)**
Target common "default" patterns used during onboarding. Avoid locking accounts by spraying slowly (1 attempt per hour).

```bash
# Using Kerbrute for on-prem AD (Stealthy - no failed login events if Pre-Auth disabled)
./kerbrute passwordspray -d target.local users.txt "Welcome123!"

# Using generic spray tool for Entra ID
./spray.sh -u users.txt -p "Company2025!" -url https://login.microsoftonline.com
```

**Step 3: Exploitation (Infrastructure Defaults)**
Check for known service accounts often left default.
*   **Azure AD Connect LocalDB:** The `(localdb)\.\ADSync` instance often allows local admin connection if accessible.
*   **Printers:** `canon_admin` / `canonical`

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID / AD Logs
Monitor for multiple accounts failing login from the **same IP** with the **same password hash** (if visible) or simply high volume of failures from one source.

#### 5.2 Microsoft Sentinel (KQL)
Detect a "Password Spray" pattern: Single IP, Many Accounts, Few Failures per Account (to avoid lockout).

```kusto
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 50126 // Invalid username or password
| summarize FailedAccounts = dcount(UserPrincipalName) by IPAddress, BinTime = bin(TimeGenerated, 1h)
| where FailedAccounts > 10
| project BinTime, IPAddress, FailedAccounts
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Identity:** Enforce **Banned Password Lists** (Entra ID Password Protection) to block terms like "Welcome", "Password", and the Company Name.
*   **Process:** Use **Temporary Access Passes (TAP)** in Entra ID for onboarding users instead of setting a password. This forces a strong FIDO2/MFA registration immediately.
*   **Smart Lockout:** Ensure Entra ID Smart Lockout is configured to block the *attacker's IP* rather than locking the *user's account*.

## 7. ATTACK CHAIN
> **Preceding Technique:** [REC-AD-002] (Username Enumeration)
> **Next Logical Step:** [IA-PHISH-005] (Internal Phishing)
