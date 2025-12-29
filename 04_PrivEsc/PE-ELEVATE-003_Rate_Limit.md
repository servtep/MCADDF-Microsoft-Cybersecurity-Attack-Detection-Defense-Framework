# [PE-ELEVATE-003]: API Rate Limiting Bypass (Service Exhaustion)

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | PE-ELEVATE-003 |
| **MITRE ATT&CK v18.1** | [Endpoint Denial of Service: Service Exhaustion (T1499.002)](https://attack.mitre.org/techniques/T1499/002/) |
| **Tactic** | Defense Evasion / Privilege Escalation (Theoretical) |
| **Platforms** | Entra ID / M365 |
| **Severity** | **Low** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** While not a direct privilege escalation, bypassing rate limits allows attackers to perform massive brute-force attacks against permissions (e.g., trying to add oneself to thousands of Groups or trying to guess Service Principal credentials). By rotating User Agents, IPs (using proxies like AWS API Gateway), and using Batch Requests in Graph API (`$batch`), attackers can bypass standard throttling to speed up enumeration or password spraying against high-value accounts.
- **Attack Surface:** Microsoft Graph API.
- **Business Impact:** **Accelerated Attacks**.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Authenticated User (for enumeration).
- **Tools:**
    - [FireProx](https://github.com/ustayready/fireprox)
    - Custom Python Scripts

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Setup FireProx**
Deploy an AWS API Gateway pass-through to rotate source IPs.

**Step 2: Batch Requests**
Use JSON batching to send 20 requests in one HTTP packet.
```json
POST /v1.0/$batch
{
  "requests": [
    {"id": "1", "method": "GET", "url": "/users/admin1@..."},
    {"id": "2", "method": "GET", "url": "/users/admin2@..."}
  ]
}
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Entra ID Logs
| Source | Event | Filter Logic |
|---|---|---|
| **SignInLogs** | `Failure` | High volume of failures from changing IPs (FireProx signature). |

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Smart Lockout:** Ensure Entra ID Smart Lockout is configured to block attacks at the tenant level, regardless of IP rotation.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-RECON-005]
> **Next Logical Step:** [IA-PASS-001]
