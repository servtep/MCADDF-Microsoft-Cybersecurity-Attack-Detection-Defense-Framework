# [PE-TOKEN-008]: API Authentication Token Manipulation (Golden SAML/OIDC)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-TOKEN-008 |
| **MITRE ATT&CK v18.1** | [Use Alternative Authentication Material: Web Session Cookie (T1550.004)](https://attack.mitre.org/techniques/T1550/004/) |
| **Tactic** | Privilege Escalation / Persistence |
| **Platforms** | Entra ID / ADFS |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** If an attacker compromises the **Token Signing Certificate** of an Identity Provider (ADFS, or a stolen key for a Service Principal), they can forge authentication tokens (SAML or OIDC JWTs) with arbitrary claims. This allows them to effectively "manipulate" the API token to grant themselves `Role: GlobalAdmin` or `scp: User.ReadWrite.All` without actually having those permissions assigned in the directory.
- **Attack Surface:** Signing Keys (ADFS DKM, Azure Key Vault).
- **Business Impact:** **Cloud Takeover**. Bypassing MFA and RBAC.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Possession of Signing Key.
- **Tools:**
    - [ADFSpoof](https://github.com/mandiant/ADFSpoof)
    - [o365-attack-toolkit](https://github.com/mdsecactivebreach/o365-attack-toolkit)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Forge Token**
Create a SAML response with the `ImmutableID` of the target Global Admin.
```bash
python3 adfspoof.py -b <Key> -s "urn:federation:MicrosoftOnline" --upn "admin@target.com" --immutable-id "1234..."
```

**Step 2: Present to API**
Use the forged SAML response to request an OAuth Access Token from Entra ID (`login.microsoftonline.com`).

**Step 3: Access Graph API**
Use the resulting JWT to perform admin actions.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Federated` | Authentication valid but no corresponding log on the on-prem IdP. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **HSM:** Protect signing keys in HSMs.
*   **Cloud Auth:** Move from Federation (ADFS) to Cloud Auth (PHS) to eliminate the attack surface of on-prem signing keys.

## 7. ATTACK CHAIN
> **Preceding Technique:** [CA-UNSC-019]
> **Next Logical Step:** [LAT-CLOUD-001]
