# [IA-PHISH-004]: Company Branding Login Poisoning

## Metadata
| Attribute | Details |
|---|---|
| **Technique ID** | IA-PHISH-004 |
| **MITRE ATT&CK v18.1** | [Phishing: Spearphishing Link (T1566.002)](https://attack.mitre.org/techniques/T1566/002/) |
| **Tactic** | Initial Access |
| **Platforms** | Entra ID (Azure AD) |
| **Severity** | **High** |
| **Author** | SERVTEP (Pchelnikau Artur) |

## 2. EXECUTIVE SUMMARY
- **Concept:** An attacker invites a victim to a malicious guest tenant controlled by the attacker. The attacker configures the tenant's "Company Branding" (Logos, Backgrounds, Sign-in Text) to mimic the victim's *own* organization or a trusted partner/vendor. When the victim accesses the invitation link, they see a familiar login screen, increasing trust and the likelihood of entering credentials or consenting to apps.
- **Attack Surface:** The B2B Guest Invite flow and Entra ID Custom Branding features.
- **Business Impact:** **User Deception** leading to credential harvesting or consent to malicious applications within the guest context.

## 3. PREREQUISITES & CONFIGURATION
- **Required Privileges:** Global Admin on the *Attacker's* tenant (to change branding).
- **Vulnerable Config:**
    - Victim tenant allows users to accept external invitations (default).
    - Victim tenant does not enforce "Cross-tenant access settings" (Inbound/Outbound trust).
- **Tools:**
    - Azure Portal (GUI)
    - PowerShell (AzureAD Module)

## 4. ATTACK (Red Team Operations)

#### 4.1 Usage
**Step 1: Preparation (Poison Branding)**
1.  In the Attacker Tenant, go to **Entra ID > User experiences > Company branding**.
2.  Upload the Victim's corporate logo (scraped from their public site).
3.  Upload the Victim's standard background image.
4.  Set the "Sign-in page text" to something authoritative like: *"Authorized Personnel Only. Please sign in to view the secure document."*

**Step 2: Exploitation (Send Invite)**
Send a B2B invite to the victim. This can be done via the portal or PowerShell.

```powershell
# Invite victim to the poisoned tenant
# Redirect URL could point to a malicious app or fake document
New-AzureADMSInvitation `
    -InvitedUserEmailAddress "victim@target-corp.com" `
    -InviteRedirectUrl "https://myapps.microsoft.com" `
    -SendInvitationMessage $true `
    -InvitedUserMessageInfo @{customizedMessageBody="Please review the attached contract."}
```

*Result:* The victim receives an official email from Microsoft. Clicking the link takes them to `login.microsoftonline.com` (legitimate URL), but the *background and logo* match their own company, making them feel safe to authenticate.

## 5. DETECTION (Blue Team Operations)

#### 5.1 Email Security
Inspect inbound emails from `invites@microsoft.com`.
*   **Logic:** Does the "Inviting Organization" name (displayed in the email body) match the branding context?
*   **Difficulty:** High. The email comes from a legitimate Microsoft sender.

#### 5.2 Microsoft Sentinel (KQL)
Detect unusual volume of B2B invites being accepted by internal users from unknown tenants.

```kusto
AuditLogs
| where OperationName == "Redeem external user invitation"
| extend InvitingTenantId = tostring(TargetResources[0].modifiedProperties[0].newValue)
| summarize count() by InvitingTenantId, InitiatedBy.user.userPrincipalName
| where count_ > 5 // Threshold for mass invites
| project InvitingTenantId, count_
```

## 6. DEFENSE & REMEDIATION (Hardening)

#### 6.2 Immediate Remediation
*   **Identity (Cross-Tenant Access):**
    *   Configure **Cross-tenant access settings** (External Identities).
    *   **Inbound access:** Restrict B2B collaboration to *only* specific trusted domains (Allow-list). Block all others.
    *   **Outbound access:** Prevent your users from being invited to arbitrary tenants. Block users from joining external tenants unless the domain is on an allow-list.
*   **Policy:**
    *   Go to **External collaboration settings**.
    *   Set "Who can invite guests" to **"Only users assigned to specific admin roles"**.

## 7. ATTACK CHAIN
> **Preceding Technique:** [REC-AD-001] (Reconnaissance of target branding)
> **Next Logical Step:** [IA-PHISH-002] (Consent Phishing once inside the guest tenant)
