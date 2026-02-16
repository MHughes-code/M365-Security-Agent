using OpenAI.Chat;
using System.Text.Json;

namespace SecurityAgent.Services;

public class ToolDefinitionService
{
    public IList<ChatTool> GetAllTools()
    {
        return new List<ChatTool>
        {
            // ═══════════════════════════════════════════════════
            // TIER 1: Targeted API Queries (auto-execute)
            // ═══════════════════════════════════════════════════

            ChatTool.CreateFunctionTool(
                functionName: "resolve_user",
                functionDescription: "Look up an Entra ID user by display name, UPN, or email. Returns user ID, UPN, and display name.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        search_term = new { type = "string", description = "Username, display name, or email to search for" }
                    },
                    required = new[] { "search_term" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_risk_detections",
                functionDescription: "Get risk detections for a user within a date range. Returns risk level, detection type, IP, location, timestamp.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        user_id = new { type = "string", description = "Entra ID user object ID" },
                        since = new { type = "string", description = "ISO 8601 date — return detections after this date" }
                    },
                    required = new[] { "user_id" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_risky_sign_ins",
                functionDescription: "Get sign-in logs flagged as risky for a user. Includes conditional access results, MFA status, device, IP, risk detail.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        user_id = new { type = "string", description = "Entra ID user object ID" },
                        since = new { type = "string", description = "ISO 8601 date" },
                        risk_level = new { type = "string", description = "Filter: low, medium, high, or none" }
                    },
                    required = new[] { "user_id" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_vulnerable_machines",
                functionDescription: "Get machines from Defender for Endpoint filtered by type and exposure. Returns name, OS, health, exposure level.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        device_type = new { type = "string", description = "e.g., Laptop, Desktop, Server" },
                        min_exposure = new { type = "string", description = "Minimum exposure: Low, Medium, High" }
                    }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_machine_vulnerabilities",
                functionDescription: "Get CVEs affecting a specific machine. Returns CVE ID, severity, affected software, description.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        machine_id = new { type = "string", description = "Defender machine ID" },
                        min_severity = new { type = "string", description = "Minimum CVSS: Low, Medium, High, Critical" }
                    },
                    required = new[] { "machine_id" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_security_recommendations",
                functionDescription: "Get security recommendations from Defender filtered by CVE or software. Returns title, remediation, severity, device count.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        related_cve = new { type = "string", description = "Filter by CVE ID" },
                        related_software = new { type = "string", description = "Filter by software product name" }
                    }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_incidents",
                functionDescription: "Get security incidents from Defender XDR. Returns incident ID, title, severity, status, affected entities.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        severity = new { type = "string", description = "Filter: informational, low, medium, high" },
                        status = new { type = "string", description = "Filter: active, resolved, redirected" },
                        since = new { type = "string", description = "ISO 8601 date" }
                    }
                })
            ),

            // ── Intune / Device Management ──

            ChatTool.CreateFunctionTool(
                functionName: "get_device_compliance_summary",
                functionDescription: "Get a summary of Intune device compliance across the tenant. Returns total devices, compliant/noncompliant/unknown counts, and breakdown by OS. Use for questions like 'how many devices are compliant' or 'device compliance overview'.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new { }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_noncompliant_devices",
                functionDescription: "Get a list of noncompliant devices from Intune with device name, OS, user, and last sync time. Optionally filter by OS (Windows, iOS, Android, macOS).",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        os_filter = new { type = "string", description = "Optional OS filter: Windows, iOS, Android, macOS" }
                    }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_devices_by_user",
                functionDescription: "Get all devices assigned to a specific user in Intune. Search by UPN (email) or partial username. Returns device name, compliance state, OS, model, and last sync. Use this when asked 'what device does [user] have' or 'which device is assigned to [user]'.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        user = new { type = "string", description = "User principal name (email) or partial username to search for" }
                    },
                    required = new[] { "user" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_compliance_policies",
                functionDescription: "Get Intune device compliance policies with their assignments and status overview. Shows which policies are deployed and their compliance rates.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new { }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_windows_update_rings",
                functionDescription: "Get Windows Update for Business configuration rings. Shows update ring settings and deployment status.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new { }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_windows_update_status",
                functionDescription: "Get Windows Update deployment status summary. Shows how many devices have pending updates, failed updates, and successful updates.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new { }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_intune_device_details",
                functionDescription: "Get detailed Intune information for a specific device by name. Returns compliance state, OS, encryption status, storage, enrollment date, and user assignment.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        device_name = new { type = "string", description = "Device/computer name to look up" }
                    },
                    required = new[] { "device_name" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_stale_devices",
                functionDescription: "Get devices that haven't synced with Intune recently. Useful for finding abandoned or offline devices. Default is 30 days of inactivity.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        days_inactive = new { type = "integer", description = "Number of days since last sync (default: 30)" }
                    }
                })
            ),

            // ═══════════════════════════════════════════════════
            // TIER 2: Template Hunting Queries (auto-execute)
            // ═══════════════════════════════════════════════════

            ChatTool.CreateFunctionTool(
                functionName: "hunt_emails",
                functionDescription: "Search email events by sender/recipient address within a date range. Auto-executes a pre-built KQL template against Advanced Hunting.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        email_address = new { type = "string", description = "Sender or recipient email address to search for" },
                        start_date = new { type = "string", description = "Start date (ISO 8601, e.g. 2026-01-15)" },
                        end_date = new { type = "string", description = "End date (ISO 8601, e.g. 2026-01-20)" }
                    },
                    required = new[] { "email_address", "start_date", "end_date" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "hunt_emails_by_subject",
                functionDescription: "Search emails by subject keyword within a date range. Auto-executes a pre-built KQL template.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        keyword = new { type = "string", description = "Subject keyword to search for" },
                        start_date = new { type = "string", description = "Start date (ISO 8601)" },
                        end_date = new { type = "string", description = "End date (ISO 8601)" }
                    },
                    required = new[] { "keyword", "start_date", "end_date" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "hunt_sign_in_activity",
                functionDescription: "Get detailed sign-in activity for a user from Advanced Hunting (richer than Graph API). Auto-executes.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        user_upn = new { type = "string", description = "User principal name (email)" },
                        start_date = new { type = "string", description = "Start date (ISO 8601)" },
                        end_date = new { type = "string", description = "End date (ISO 8601)" }
                    },
                    required = new[] { "user_upn", "start_date", "end_date" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "hunt_device_activity",
                functionDescription: "Get process, network, and file activity for a device from Advanced Hunting. Auto-executes.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        device_name = new { type = "string", description = "Device/computer name" },
                        start_date = new { type = "string", description = "Start date (ISO 8601)" },
                        end_date = new { type = "string", description = "End date (ISO 8601)" }
                    },
                    required = new[] { "device_name", "start_date", "end_date" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "hunt_cloud_activity",
                functionDescription: "Get cloud app activity (SharePoint, OneDrive, Teams, Exchange) for a user. Auto-executes.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        user_name = new { type = "string", description = "User display name or UPN" },
                        start_date = new { type = "string", description = "Start date (ISO 8601)" },
                        end_date = new { type = "string", description = "End date (ISO 8601)" }
                    },
                    required = new[] { "user_name", "start_date", "end_date" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "hunt_email_urls",
                functionDescription: "Search for URLs in emails — by URL pattern or by recipient. Auto-executes.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        url_pattern = new { type = "string", description = "URL or domain to search for (partial match)" },
                        email_address = new { type = "string", description = "Filter by recipient email" },
                        start_date = new { type = "string", description = "Start date (ISO 8601)" },
                        end_date = new { type = "string", description = "End date (ISO 8601)" }
                    },
                    required = new[] { "start_date", "end_date" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "hunt_device_vulnerabilities",
                functionDescription: "Get a summary of CVE vulnerabilities across all devices, grouped by device. Shows CVE count, max CVSS score, exploitable count, and zero-day count per device. Use this instead of get_machine_vulnerabilities when querying across multiple or all devices. Auto-executes.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        min_severity = new { type = "string", description = "Minimum severity to include: Critical, High, Medium, Low. Can combine with comma: 'Critical,High'" }
                    },
                    required = new[] { "min_severity" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "hunt_device_vulnerabilities_detail",
                functionDescription: "Get detailed CVE list for a specific device — individual CVEs with CVSS scores, affected software, exploit availability, and recommended updates. Use after hunt_device_vulnerabilities to drill into a specific machine. Auto-executes.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        device_name = new { type = "string", description = "Device/computer name to get vulnerabilities for" },
                        min_severity = new { type = "string", description = "Minimum severity: Critical, High, Medium, Low. Can combine: 'Critical,High'" }
                    },
                    required = new[] { "device_name", "min_severity" }
                })
            ),

            // ── SharePoint / Guest Access ──

            ChatTool.CreateFunctionTool(
                functionName: "get_guest_users",
                functionDescription: "List all guest/external users in the tenant. Returns display name, email, account status, and when they were invited. Use when asked about external users, guests, or outside access.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new { }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "get_guest_user_details",
                functionDescription: "Get details on a specific guest user including sign-in activity and account state. Requires the guest user's Entra ID (object ID).",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        guest_id = new { type = "string", description = "Guest user's Entra ID object ID" }
                    },
                    required = new[] { "guest_id" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "hunt_external_sharing",
                functionDescription: "Search for files and folders shared externally (outside the organization) in SharePoint and OneDrive. Shows who shared what, with whom, and when. Auto-executes.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        start_date = new { type = "string", description = "Start date (ISO 8601)" },
                        end_date = new { type = "string", description = "End date (ISO 8601)" }
                    },
                    required = new[] { "start_date", "end_date" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "hunt_user_sharing_activity",
                functionDescription: "Search for all sharing activity by a specific user in SharePoint and OneDrive. Shows what they shared, with whom, and when. Auto-executes.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        user_name = new { type = "string", description = "User display name or UPN to search for" },
                        start_date = new { type = "string", description = "Start date (ISO 8601)" },
                        end_date = new { type = "string", description = "End date (ISO 8601)" }
                    },
                    required = new[] { "user_name", "start_date", "end_date" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "hunt_guest_activity",
                functionDescription: "Search for what a specific guest/external user has accessed in SharePoint and OneDrive. Shows files viewed, downloaded, and sites visited. Auto-executes.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        guest_email = new { type = "string", description = "Guest user's email address" },
                        guest_name = new { type = "string", description = "Guest user's display name (optional, used as fallback)" },
                        start_date = new { type = "string", description = "Start date (ISO 8601)" },
                        end_date = new { type = "string", description = "End date (ISO 8601)" }
                    },
                    required = new[] { "guest_email", "start_date", "end_date" }
                })
            ),

            // ═══════════════════════════════════════════════════
            // TIER 3: Dynamic KQL (requires human approval)
            // ═══════════════════════════════════════════════════

            ChatTool.CreateFunctionTool(
                functionName: "propose_advanced_hunting_query",
                functionDescription: "Generate a custom KQL query for advanced threat hunting. Does NOT execute — returns the query for user approval. Use ONLY when no Tier 1 or Tier 2 tool can answer the question.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        kql_query = new { type = "string", description = "The full KQL query to execute against Advanced Hunting" },
                        explanation = new { type = "string", description = "Plain-English explanation of what this query does and what tables/data it accesses" },
                        estimated_scope = new { type = "string", description = "Estimated data scope: narrow (single user/device), medium (department/timeframe), broad (tenant-wide)" }
                    },
                    required = new[] { "kql_query", "explanation", "estimated_scope" }
                })
            ),

            ChatTool.CreateFunctionTool(
                functionName: "execute_approved_hunting_query",
                functionDescription: "Execute a KQL query previously proposed and approved by the user. ONLY call this after the user has explicitly approved the query (said 'yes', 'run it', 'go ahead', etc.).",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        kql_query = new { type = "string", description = "The exact KQL query that was approved by the user" }
                    },
                    required = new[] { "kql_query" }
                })
            ),

            // ── Report Generation Tools ──
            ChatTool.CreateFunctionTool(
                functionName: "generate_security_report",
                functionDescription: "Generate branded HTML security reports and upload to SharePoint. Optionally email the report. Use when the user asks to 'generate a report', 'create the security report', 'email me the report', etc.",
                functionParameters: BinaryData.FromObjectAsJson(new
                {
                    type = "object",
                    properties = new
                    {
                        report_type = new { type = "string", @enum = new[] { "devices", "sharepoint", "both" }, description = "Which report: 'devices' for Devices & Vulnerabilities, 'sharepoint' for SharePoint & External Access, 'both' for both reports" },
                        send_email = new { type = "boolean", description = "If true, also send email notification with link to the report" },
                        email_to = new { type = "string", description = "Optional override email address (defaults to configured recipients)" }
                    },
                    required = new[] { "report_type" }
                })
            )
        };
    }
}
