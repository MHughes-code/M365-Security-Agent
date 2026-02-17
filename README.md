# Microsoft 365 Security Agent

An AI-powered security operations assistant built on Azure Functions that integrates with Microsoft 365, Defender for Endpoint, Intune, and SharePoint. It provides natural-language security investigations through a Microsoft Teams bot and generates branded biweekly security reports.

## What It Does

**Interactive Security Investigations (via Teams Bot)**
- Resolve user identities and review sign-in activity, risky sign-ins, and MFA status
- Query device compliance, noncompliant devices, and stale device detection
- Search vulnerabilities across devices with CVSS scoring and remediation guidance
- Investigate email activity, cloud app events, and SharePoint external sharing
- Run Advanced Hunting (KQL) queries with human approval workflows
- Manage Intune device compliance, update rings, and Windows update status

**Automated Security Reports**
- Branded HTML reports with your organization's logo and colors
- Devices & Vulnerabilities Report: compliance summary, critical CVEs, update status, stale devices
- SharePoint & External Access Report: external sharing activity, guest users, expiring access
- Biweekly scheduled generation (1st and 15th of each month)
- On-demand generation via Teams bot or HTTP endpoint
- Uploads to SharePoint document library with email notification and HTML attachment

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Teams Bot   │────▶│  Azure Function   │────▶│  Azure OpenAI   │
│  (User UI)   │◀────│  (Orchestrator)   │◀────│  (GPT-4.1-mini) │
└─────────────┘     └──────────────────┘     └─────────────────┘
                            │
                    ┌───────┼───────┐
                    ▼       ▼       ▼
              ┌──────┐ ┌────────┐ ┌──────────┐
              │Graph │ │Defender│ │ Advanced  │
              │ API  │ │  API   │ │ Hunting   │
              └──────┘ └────────┘ └──────────┘
                │           │          │
           ┌────┴────┐  ┌──┴───┐  ┌──┴──────┐
           │Identity  │  │Device │  │  KQL    │
           │Intune    │  │Vulns  │  │ Queries │
           │SharePoint│  │Alerts │  │         │
           └──────────┘  └──────┘  └─────────┘
```

**Three-Tier Query System:**
1. **Tier 1** — Direct API calls (user lookups, compliance checks, device details)
2. **Tier 2** — Template-based KQL queries (vulnerability scans, email analysis, sign-in investigations)
3. **Tier 3** — Dynamic KQL queries with human approval (custom investigations)

## Prerequisites

- **Azure Subscription** with permissions to create resources
- **Microsoft 365 tenant** with Defender for Endpoint (P2 recommended)
- **Azure OpenAI Service** with a GPT-4.1-mini (or similar) deployment
- **.NET 8 SDK** installed locally
- **Azure Functions Core Tools v4** for local development
- **Azure CLI** or **VS Code with Azure Functions extension** for deployment

## Setup Guide

### 1. Create the App Registration

1. Go to **Entra ID** → **App registrations** → **New registration**
2. Name: `Security Agent` (or your preference)
3. Supported account types: **Single tenant**
4. No redirect URI needed
5. After creation, note the **Application (client) ID** and **Directory (tenant) ID**
6. Go to **Certificates & secrets** → **New client secret** → note the value

### 2. Configure API Permissions

In your app registration → **API permissions** → **Add a permission**:

**Microsoft Graph (Application permissions):**
| Permission | Purpose |
|---|---|
| `User.Read.All` | User identity lookups |
| `AuditLog.Read.All` | Sign-in and audit logs |
| `Directory.Read.All` | Directory data |
| `DeviceManagementManagedDevices.Read.All` | Intune device compliance |
| `DeviceManagementConfiguration.Read.All` | Intune policies and update rings |
| `Sites.ReadWrite.All` | SharePoint report uploads |
| `Mail.Send` | Email report delivery |
| `IdentityRiskEvent.Read.All` | Risky sign-in detection |

**Microsoft Threat Protection (Application permissions):**
| Permission | Purpose |
|---|---|
| `AdvancedHunting.Read.All` | KQL Advanced Hunting queries |

**WindowsDefenderATP (Application permissions):**
| Permission | Purpose |
|---|---|
| `Vulnerability.Read.All` | Device vulnerability data |
| `Machine.Read.All` | Defender device inventory |

After adding all permissions, click **Grant admin consent** for your tenant.

### 3. Set Up Azure OpenAI

1. Create an **Azure OpenAI** resource in your subscription
2. Deploy a model (recommended: `gpt-4.1-mini` for cost efficiency)
3. Note the **Endpoint URL** and **API Key** from the resource's Keys and Endpoint page
4. Note the **Deployment Name** you chose

### 4. Configure the Project

1. Clone this repository
2. Copy `local.settings.template.json` to `local.settings.json`
3. Fill in your values:

```json
{
  "Values": {
    "AgentConfiguration:TenantId": "your-tenant-id",
    "AgentConfiguration:ClientId": "your-app-client-id",
    "AgentConfiguration:ClientSecret": "your-client-secret",
    "AgentConfiguration:OpenAiEndpoint": "https://your-resource.openai.azure.com/",
    "AgentConfiguration:OpenAiApiKey": "your-api-key",
    "AgentConfiguration:DeploymentName": "your-deployment-name"
  }
}
```

### 5. Customize for Your Organization

**System Prompt** — Edit `Services/AgentOrchestrator.cs` and replace organization-specific references:
- Company name in the system prompt header
- Domain name references (e.g., `yourdomain.com` → `yourdomain.com`)
- Any role or team references

**Report Branding** — The HTML reports use these configurable elements:
- Logo: Set `ReportLogoSvgBase64` to your base64-encoded SVG logo
- Colors: Edit the CSS variables in `Services/ReportGeneratorService.cs` (search for `CssStyles`)
- Footer text: Update the company name in `GetFooter()` method

To encode your SVG logo:
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("path\to\your-logo.svg"))
```

### 6. Deploy to Azure

**Create the Azure Function App:**
```bash
az functionapp create \
  --resource-group your-resource-group \
  --consumption-plan-location your-location-of-choice \
  --runtime dotnet-isolated \
  --runtime-version 8 \
  --functions-version 4 \
  --name your-security-agent \
  --storage-account yourstorageaccount
```

**Deploy the code:**
```bash
# From the project directory
func azure functionapp publish your-security-agent
```

**Configure App Settings** in the Azure Portal (Function App → Configuration):

Add each setting from `local.settings.template.json` as an Application Setting, using the double-underscore format:
```
AgentConfiguration__TenantId          → your-tenant-id
AgentConfiguration__ClientId          → your-app-client-id
AgentConfiguration__ClientSecret      → your-client-secret
AgentConfiguration__OpenAiEndpoint    → https://your-resource.openai.azure.com/
AgentConfiguration__OpenAiApiKey      → your-api-key
AgentConfiguration__DeploymentName    → your-deployment-name
```

> **Important:** Do not put quotes around values in Azure App Settings. The values are already treated as strings.

### 7. Set Up the Teams Bot

1. Go to the **Azure Portal** → **Create a resource** → **Azure Bot**
2. Configure:
   - **Bot handle**: `your-security-agent-bot`
   - **App type**: Multi Tenant or Single Tenant
   - **App ID**: Create new or use existing (note the ID and password)
3. In the bot resource → **Channels** → Add **Microsoft Teams**
4. In **Configuration** → **Messaging endpoint**: `https://your-security-agent.azurewebsites.net/api/messages`
5. Add the bot App ID and password to your Function App settings:
   ```
   BotConfiguration__MicrosoftAppId       → your-bot-app-id
   BotConfiguration__MicrosoftAppPassword → your-bot-app-password
   ```

**Create the Teams App Package:**
1. Create a `manifest.json` for your Teams app (see [Microsoft docs](https://learn.microsoft.com/en-us/microsoftteams/platform/resources/schema/manifest-schema))
2. Include your bot ID in the manifest
3. Package as a `.zip` with the manifest and two icon files (color + outline)
4. Upload to Teams Admin Center or sideload for testing

### 8. Configure Report Settings

These are only needed if you want automated/on-demand reports:

| Setting | Description | How to Get |
|---|---|---|
| `ReportSharePointSiteId` | SharePoint site ID for uploads | `GET https://graph.microsoft.com/v1.0/sites?search=YourSite` |
| `ReportDocumentLibrary` | Document library drive name | Usually `Documents` or `Shared Documents` |
| `ReportFolderPath` | Subfolder path within the library | e.g., `IT Reports/Security Reports` |
| `ReportSharedMailbox` | Shared mailbox for sending reports | e.g., `security@yourdomain.com` |
| `ReportRecipients` | Default email recipients (comma-separated) | e.g., `admin@yourdomain.com,it@yourdomain.com` |
| `ReportTeamsWebhookUrl` | Teams incoming webhook URL (optional) | Create via Teams channel → Workflows |
| `ReportLogoSvgBase64` | Base64-encoded SVG logo for report header | See Step 5 above |
| `OrganizationDomain` | Domain restriction for report emails | e.g., `yourdomain.com` |

**Create the SharePoint Document Library:**
Make sure the folder path exists in your SharePoint site's document library before generating reports. Graph API will auto-create subfolders, but the root library must exist.

## Usage

### Teams Bot Commands (Natural Language)

The bot understands natural language — no rigid command syntax needed:

**Identity & Access:**
- "Look up john.doe" / "Who is john.doe@yourdomain.com?"
- "Show me risky sign-ins for the past week"
- "Check MFA status for the finance team"

**Devices & Compliance:**
- "Show me noncompliant devices"
- "How many stale devices do we have?"
- "Get compliance summary"

**Vulnerabilities:**
- "Show critical vulnerabilities"
- "What vulnerabilities does SRV-WEB-01 have?"
- "Find devices with CVE-2024-12345"

**Investigations:**
- "Check external sharing activity this month"
- "Show me email activity for john.doe"
- "Who has guest access to our SharePoint?"

**Reports:**
- "Generate the devices report"
- "Generate both reports and email them to me"
- "Generate the SharePoint report and email it to admin@yourdomain.com and hr@yourdomain.com"

**Advanced Hunting:**
- "Find all sign-ins from outside Canada in the last 24 hours"
- The bot will propose a KQL query and wait for your approval before executing

### HTTP Endpoints

**On-demand report generation:**
```bash
# Generate devices report
curl -X POST https://your-function.azurewebsites.net/api/generate-report \
  -H "Content-Type: application/json" \
  -d '{"report": "devices"}'

# Generate both reports with email
curl -X POST https://your-function.azurewebsites.net/api/generate-report \
  -H "Content-Type: application/json" \
  -d '{"report": "both", "email": true}'

# Generate and email to specific person
curl -X POST https://your-function.azurewebsites.net/api/generate-report \
  -H "Content-Type: application/json" \
  -d '{"report": "devices", "email": true, "emailTo": "user@yourdomain.com"}'
```

**Direct agent query:**
```bash
curl -X POST https://your-function.azurewebsites.net/api/security-agent \
  -H "Content-Type: application/json" \
  -d '{"query": "show me noncompliant devices"}'
```

### Scheduled Reports

Reports are automatically generated on the **1st and 15th of each month at 7:00 AM** (configurable via the CRON expression in `Functions/ReportFunction.cs`). The schedule is:
- `0 0 11 1,15 * *` (11:00 UTC = 7:00 AM AST / 8:00 AM ADT)

To change the schedule, modify the `TimerTrigger` CRON expression. The format is `{second} {minute} {hour} {day} {month} {day-of-week}`.

## Project Structure

```
SecurityAgent/
├── Bot/
│   ├── SecurityAgentBot.cs          # Teams bot message handler
│   ├── AdaptiveCardBuilder.cs       # Rich card formatting for Teams
│   ├── MessageFormatter.cs          # Text formatting with emoji
│   └── AdapterWithErrorHandler.cs   # Bot error handling
├── Config/
│   ├── AgentConfiguration.cs        # Main configuration model
│   └── BotConfiguration.cs          # Bot-specific config
├── Functions/
│   ├── BotMessagesFunction.cs       # Teams webhook endpoint
│   ├── SecurityAgentFunction.cs     # HTTP query endpoint
│   └── ReportFunction.cs            # Scheduled + on-demand reports
├── Models/
│   └── AgentResponse.cs             # Response models
├── Services/
│   ├── AgentOrchestrator.cs         # GPT orchestration + system prompt
│   ├── ToolDefinitionService.cs     # Tool/function definitions for GPT
│   ├── ToolExecutionService.cs      # Tool call execution logic
│   ├── GraphApiService.cs           # Microsoft Graph API (identity, SharePoint)
│   ├── DefenderApiService.cs        # Defender for Endpoint API
│   ├── AdvancedHuntingService.cs    # KQL templates + dynamic queries
│   ├── IntuneService.cs             # Intune device management
│   ├── ReportGeneratorService.cs    # HTML report generation
│   ├── SharePointService.cs         # SharePoint file uploads
│   ├── EmailService.cs              # Email with attachments via Graph
│   ├── TokenService.cs              # OAuth token management
│   └── ConversationStateService.cs  # Multi-turn conversation state
├── Program.cs                       # DI registration + startup
├── host.json                        # Azure Functions host config
├── local.settings.template.json     # Template for local development
└── .gitignore
```

## Estimated Operating Cost

This application primarily incurs cost from Azure OpenAI usage.  
All Microsoft Graph, Defender for Endpoint, Intune, SharePoint, and email operations are covered under existing Microsoft 365 licensing and do not generate additional Azure charges.

The current recommended model is **gpt-4.1-mini**, chosen for cost-efficient reasoning and tool orchestration.

---

### 🔎 Normal Monthly Usage (≤300 Investigations)

Assumptions:
- ~5,000 tokens per investigation (system prompt + tool definitions + tool responses + final answer)
- ~300 investigations per month
- ~20% of investigations involve Advanced Hunting (Tier 3)
- 2 scheduled reports per month

| Component | Estimated Monthly Cost |
|------------|------------------------|
| Base investigations | $6–$10 |
| Advanced Hunting (Tier 3) | $2–$4 |
| Report generation | <$1 |
| Azure Functions + Storage | $0–$10 |

**Estimated total monthly cost:**  
### **$10–$25**

---

### 🚨 Incident Response Scenario (Usage Doubles)

If investigation volume increases to ~600 per month during active incident response:

- Increased Tier 3 usage (~40%)
- Slightly higher token usage per investigation

| Component | Estimated Monthly Cost |
|------------|------------------------|
| OpenAI usage | ~$26 |
| Azure Functions + Storage | $5–$15 |

**Estimated total during an active incident:**  
### **$30–$45**

---

### 💣 Extreme High-Usage Scenario

If usage increases significantly (1,000 investigations with heavy Advanced Hunting):

- ~10,000 tokens average per investigation

Estimated OpenAI cost:
~$40

Including compute overhead:

### **$50–$75 total for a very high-usage month**

---

### 🧠 Optional Hybrid Model Strategy

If Tier 3 investigations are upgraded to **gpt-4o** while keeping Tier 1/2 on gpt-4.1-mini:

- Additional estimated cost: ~$10–$20 per month at current scale
- Expected normal monthly total: ~$20–$40

---

### Executive Cost Summary

Under normal usage (≤300 investigations per month), estimated operating expenses are approximately **$10–$25 per month**.

During elevated incident response activity, costs may increase to approximately **$30–$45 per month**, with extreme high-usage scenarios remaining under **$75 per month**.

The use of gpt-4.1-mini keeps surge usage financially manageable and predictable.


## Security Considerations

- **Client secrets** should be stored in Azure Key Vault in production, not in app settings
- **Application permissions** grant tenant-wide access — the app can read all users, devices, and mail. Scope permissions down if your use case is narrower
- **Dynamic KQL queries** (Tier 3) require human approval before execution to prevent unintended data access
- **Email domain restriction** limits report distribution to your organization domain (configured via `OrganizationDomain`)
- **Shared mailbox** sends emails as a service account rather than impersonating individual users

## Troubleshooting

**Bot returns "Something went wrong":**
- Check Azure Function logs in the portal (Function App → Monitor → Logs)
- Most common: missing or incorrect API permissions, expired client secret

**Reports show 0 for all values:**
- Verify API permissions are granted and admin-consented
- Check that the app has `DeviceManagementManagedDevices.Read.All` for Intune data
- Check function logs for specific API error responses

**Email not sending:**
- Verify `Mail.Send` permission is admin-consented
- Check that the shared mailbox exists and the app can send from it
- Check `OrganizationDomain` isn't blocking the recipient

**SharePoint upload fails:**
- Verify `Sites.ReadWrite.All` permission
- Confirm `ReportSharePointSiteId` is correct (use Graph Explorer to verify)
- Ensure the document library name in `ReportDocumentLibrary` matches exactly

**Authentication errors (401/403):**
- Token endpoints need the correct scope: `https://graph.microsoft.com/.default` for Graph, `https://api.securitycenter.microsoft.com/.default` for Defender
- Verify tenant ID, client ID, and client secret are correct
- Check that admin consent has been granted for all permissions

## License

This project is provided as-is for internal IT security operations. Modify and deploy at your own discretion.
