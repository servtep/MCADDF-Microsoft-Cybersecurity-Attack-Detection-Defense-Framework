# [IA-VALID-002]: Stale/Inactive Account Compromise

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | IA-VALID-002 |
| **MITRE ATT&CK v18.1** | [Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/) |
| **Tactic** | Initial Access |
| **Platforms** | Windows AD / Entra ID |
| **Severity** | **Medium** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Targeting accounts that have not logged in for an extended period (e.g., > 90 days). These accounts are often overlooked by security teams, may not have MFA enrolled, and often retain old, weak passwords that comply with outdated complexity policies.
- **Attack Surface:** AD User Accounts, Service Accounts, and Guests in Entra ID.
- **Business Impact:** **Stealthy Access**. Compromising a stale account allows an attacker to "live off the land" with a valid identity that security operations are not actively monitoring.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Enumeration capability (Authenticated or Anonymous).
- **Vulnerable Config:**
    - Lack of automated "Stale Account Cleanup" process.
    - Password expiration policies disabled (`PasswordNeverExpires`).
- **Tools:**
    - PowerShell (ActiveDirectory Module)
    - [PowerView](https://github.com/PowerShellMafia/PowerSploit)
    - `ldapsearch`

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Discovery (Identify Stale Accounts)**
If already inside (or via LDAP enumeration), find accounts with old `lastLogonTimestamp`.

```powershell
# PowerView: Find users inactive for > 90 days
Get-DomainUser -Properties Name,LastLogonDate,PasswordLastSet | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)}

# LDAP Filter (Convert date to FileTime first)
# (lastLogonTimestamp<=133481234560000000)
```

**Step 2: Exploitation (Targeted Attack)**
Because these users are inactive, they are prime candidates for:
1.  **AS-REP Roasting:** If they don't require Pre-Auth (common on old accounts).
2.  **Password Spray:** Using old seasonal passwords (e.g., `Summer2023!`).

```bash
# Check for AS-REP Roasting on the stale list
GetDomainUser -Identity [StaleUser] | Get-DomainUserPreauth
```

**Step 3: Persistence**
Re-enable the account if disabled (requires privileges) or simply start using it. *Note: Logging in might trigger a "First login in X days" alert if monitored.*

## 5. DETECTION (Blue Team Operations)

#### 5.1 Active Directory Analysis
Regularly audit for accounts with `lastLogonTimestamp` older than 90 days.

#### 5.2 Microsoft Sentinel (KQL)
Detect successful login to an account that has been dormant.

```kusto
let lookback = 90d;
let recent_logins = SigninLogs
| where TimeGenerated > ago(1h)
| distinct UserPrincipalName;
let historical_logins = SigninLogs
| where TimeGenerated between (ago(lookback) .. ago(1h))
| distinct UserPrincipalName;
recent_logins
| join kind=leftanti historical_logins on UserPrincipalName
| project UserPrincipalName, "Account woke up after dormancy"
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Process:** Implement an automated script to **Disable** accounts inactive for 45-90 days.
    ```powershell
    Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 | Disable-ADAccount
    ```
*   **Identity:** Enforce **Access Reviews** in Entra ID (Identity Governance) to force managers to recertify guest and user access quarterly.

## 7. ATTACK CHAIN
> **Preceding Technique:** [REC-AD-003] (Enumeration)
> **Next Logical Step:** [LAT-AD-002] (Kerberoasting the stale account)
