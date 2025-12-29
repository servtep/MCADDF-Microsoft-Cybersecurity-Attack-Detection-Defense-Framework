# [PE-ACCTMGMT-013]: Self-Service Password Reset (SSPR) Misconfiguration

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ACCTMGMT-013 |
| **MITRE ATT&CK v18.1** | [Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Entra ID |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** If "Self-Service Password Reset" is enabled for users, but an admin account has *not* yet registered their authentication methods (e.g., a newly created admin or a service account converted to a user), an attacker who guesses the password (or has `User Administrator` rights to reset it) can log in. Upon login, they will be prompted to "Register SSPR info". The attacker can then register their *own* mobile number or email. This gives them a permanent backdoor to reset the password in the future, even if the original password is changed.
- **Attack Surface:** SSPR Registration.
- **Business Impact:** **Account Takeover**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** User Administrator (to reset password initially) or compromised creds of unregistered user.
- **Tools:**
    - Browser

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Identify Unregistered Admins**
Look for admins where `StrongAuthenticationMethods` is empty or `MethodsRegistered` is false.
```powershell
Get-MgUser -Filter "assignedPlans/any(a:a/service eq 'Exchange' and a/capabilityStatus eq 'Enabled')" -Property Id, UserPrincipalName, StrongAuthenticationMethods
```

**Step 2: Login & Register**
Log in with the known/reset password.
When prompted "More information required", register an attacker-controlled Authenticator App or Phone.

**Step 3: Reset**
Use the "Forgot my password" link on the login page to reset the password using the method you just added.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `User registered security info` | Registration of security info by an administrator account from an unknown IP/Device. |
| **AuditLogs** | `Self-service password reset` | SSPR performed shortly after method registration. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Registration Campaign:** Enforce a "Registration Campaign" via Conditional Access to force all users (especially admins) to register MFA immediately upon creation.
*   **Restrict SSPR:** Don't allow SSPR for Global Admins (Microsoft default restriction usually applies, but check custom roles).

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-PASS-001]
> **Next Logical Step:** [PE-ACCTMGMT-014]
