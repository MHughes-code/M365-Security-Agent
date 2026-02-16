using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace SecurityAgent.Services;

public class ToolExecutionService
{
    private readonly GraphApiService _graphService;
    private readonly DefenderApiService _defenderService;
    private readonly AdvancedHuntingService _huntingService;
    private readonly IntuneService _intuneService;
    private readonly ReportGeneratorService _reportGenerator;
    private readonly SharePointService _sharePoint;
    private readonly EmailService _email;
    private readonly ILogger<ToolExecutionService> _logger;

    // Tracks the last proposed dynamic KQL query for approval validation
    private string? _pendingQuery;

    public ToolExecutionService(
        GraphApiService graphService,
        DefenderApiService defenderService,
        AdvancedHuntingService huntingService,
        IntuneService intuneService,
        ReportGeneratorService reportGenerator,
        SharePointService sharePoint,
        EmailService email,
        ILogger<ToolExecutionService> logger)
    {
        _graphService = graphService;
        _defenderService = defenderService;
        _huntingService = huntingService;
        _intuneService = intuneService;
        _reportGenerator = reportGenerator;
        _sharePoint = sharePoint;
        _email = email;
        _logger = logger;
    }

    /// <summary>
    /// Returns true if the last tool call was a KQL proposal awaiting approval.
    /// </summary>
    public bool IsAwaitingApproval => _pendingQuery != null;

    /// <summary>
    /// Route a tool call to the appropriate service and return the result.
    /// </summary>
    public async Task<string> ExecuteAsync(string toolName, string argumentsJson)
    {
        _logger.LogInformation("Executing tool: {Tool} with args: {Args}",
            toolName, argumentsJson.Length > 500 ? argumentsJson[..500] + "..." : argumentsJson);

        var args = JsonDocument.Parse(argumentsJson).RootElement;

        try
        {
            return toolName switch
            {
                // ── Tier 1: Targeted Queries ──
                "resolve_user" => await _graphService.ResolveUserAsync(
                    GetRequired(args, "search_term")),

                "get_risk_detections" => await _graphService.GetRiskDetectionsAsync(
                    GetRequired(args, "user_id"),
                    GetOptional(args, "since")),

                "get_risky_sign_ins" => await _graphService.GetRiskySignInsAsync(
                    GetRequired(args, "user_id"),
                    GetOptional(args, "since"),
                    GetOptional(args, "risk_level")),

                "get_vulnerable_machines" => await _defenderService.GetMachinesAsync(
                    GetOptional(args, "device_type"),
                    GetOptional(args, "min_exposure")),

                "get_machine_vulnerabilities" => await _defenderService.GetMachineVulnerabilitiesAsync(
                    GetRequired(args, "machine_id"),
                    GetOptional(args, "min_severity")),

                "get_security_recommendations" => await _defenderService.GetRecommendationsAsync(
                    GetOptional(args, "related_cve"),
                    GetOptional(args, "related_software")),

                "get_incidents" => await _graphService.GetIncidentsAsync(
                    GetOptional(args, "severity"),
                    GetOptional(args, "status"),
                    GetOptional(args, "since")),

                // ── Intune / Device Management ──
                "get_device_compliance_summary" => await _intuneService.GetDeviceComplianceSummaryAsync(),

                "get_noncompliant_devices" => await _intuneService.GetNoncompliantDevicesAsync(
                    GetOptional(args, "os_filter")),

                "get_compliance_policies" => await _intuneService.GetCompliancePoliciesAsync(),

                "get_windows_update_rings" => await _intuneService.GetWindowsUpdateRingsAsync(),

                "get_windows_update_status" => await _intuneService.GetWindowsUpdateStatusAsync(),

                "get_intune_device_details" => await _intuneService.GetDeviceDetailsAsync(
                    GetRequired(args, "device_name")),

                "get_stale_devices" => await _intuneService.GetStaleDevicesAsync(
                    args.TryGetProperty("days_inactive", out var days) ? days.GetInt32() : 30),

                "get_devices_by_user" => await _intuneService.GetDevicesByUserAsync(
                    GetRequired(args, "user")),

                // ── SharePoint / Guest Access ──
                "get_guest_users" => await _graphService.GetGuestUsersAsync(),

                "get_guest_user_details" => await _graphService.GetGuestUserDetailsAsync(
                    GetRequired(args, "guest_id")),

                // ── Tier 2: Template Hunting ──
                "hunt_emails" => await _huntingService.RunTemplateQueryAsync(
                    "search_emails",
                    new Dictionary<string, string>
                    {
                        ["email_address"] = GetRequired(args, "email_address"),
                        ["start_date"] = GetRequired(args, "start_date"),
                        ["end_date"] = GetRequired(args, "end_date")
                    }),

                "hunt_emails_by_subject" => await _huntingService.RunTemplateQueryAsync(
                    "search_emails_by_subject",
                    new Dictionary<string, string>
                    {
                        ["keyword"] = GetRequired(args, "keyword"),
                        ["start_date"] = GetRequired(args, "start_date"),
                        ["end_date"] = GetRequired(args, "end_date")
                    }),

                "hunt_sign_in_activity" => await _huntingService.RunTemplateQueryAsync(
                    "search_sign_ins",
                    new Dictionary<string, string>
                    {
                        ["user_upn"] = GetRequired(args, "user_upn"),
                        ["start_date"] = GetRequired(args, "start_date"),
                        ["end_date"] = GetRequired(args, "end_date")
                    }),

                "hunt_device_activity" => await _huntingService.RunTemplateQueryAsync(
                    "search_device_activity",
                    new Dictionary<string, string>
                    {
                        ["device_name"] = GetRequired(args, "device_name"),
                        ["start_date"] = GetRequired(args, "start_date"),
                        ["end_date"] = GetRequired(args, "end_date")
                    }),

                "hunt_cloud_activity" => await _huntingService.RunTemplateQueryAsync(
                    "search_cloud_activity",
                    new Dictionary<string, string>
                    {
                        ["user_name"] = GetRequired(args, "user_name"),
                        ["start_date"] = GetRequired(args, "start_date"),
                        ["end_date"] = GetRequired(args, "end_date")
                    }),

                "hunt_email_urls" => await _huntingService.RunTemplateQueryAsync(
                    "search_email_urls",
                    new Dictionary<string, string>
                    {
                        ["url_pattern"] = GetOptional(args, "url_pattern") ?? "",
                        ["email_address"] = GetOptional(args, "email_address") ?? "",
                        ["start_date"] = GetRequired(args, "start_date"),
                        ["end_date"] = GetRequired(args, "end_date")
                    }),

                "hunt_device_vulnerabilities" => await _huntingService.RunTemplateQueryAsync(
                    "search_device_vulnerabilities",
                    new Dictionary<string, string>
                    {
                        ["severity_filter"] = FormatSeverityFilter(GetRequired(args, "min_severity"))
                    }),

                "hunt_device_vulnerabilities_detail" => await _huntingService.RunTemplateQueryAsync(
                    "search_device_vulnerabilities_detail",
                    new Dictionary<string, string>
                    {
                        ["device_name"] = GetRequired(args, "device_name"),
                        ["severity_filter"] = FormatSeverityFilter(GetRequired(args, "min_severity"))
                    }),

                // ── SharePoint / External Sharing Hunting ──
                "hunt_external_sharing" => await _huntingService.RunTemplateQueryAsync(
                    "search_external_sharing",
                    new Dictionary<string, string>
                    {
                        ["start_date"] = GetRequired(args, "start_date"),
                        ["end_date"] = GetRequired(args, "end_date")
                    }),

                "hunt_user_sharing_activity" => await _huntingService.RunTemplateQueryAsync(
                    "search_user_sharing",
                    new Dictionary<string, string>
                    {
                        ["user_name"] = GetRequired(args, "user_name"),
                        ["start_date"] = GetRequired(args, "start_date"),
                        ["end_date"] = GetRequired(args, "end_date")
                    }),

                "hunt_guest_activity" => await _huntingService.RunTemplateQueryAsync(
                    "search_guest_activity",
                    new Dictionary<string, string>
                    {
                        ["guest_email"] = GetRequired(args, "guest_email"),
                        ["guest_name"] = GetOptional(args, "guest_name") ?? "",
                        ["start_date"] = GetRequired(args, "start_date"),
                        ["end_date"] = GetRequired(args, "end_date")
                    }),

                // ── Tier 3: Dynamic Hunting ──
                "propose_advanced_hunting_query" => HandleProposal(args),

                "execute_approved_hunting_query" => await HandleApprovedExecution(args),

                // ── Report Generation ──
                "generate_security_report" => await HandleReportGeneration(args),

                _ => JsonSerializer.Serialize(new { error = $"Unknown tool: {toolName}" })
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing tool {Tool}", toolName);
            return JsonSerializer.Serialize(new { error = $"Tool execution failed: {ex.Message}" });
        }
    }

    /// <summary>
    /// Handle a Tier 3 KQL proposal — store it but don't execute.
    /// </summary>
    private string HandleProposal(JsonElement args)
    {
        var kql = GetRequired(args, "kql_query");
        var explanation = GetRequired(args, "explanation");
        var scope = GetRequired(args, "estimated_scope");

        // Store the proposed query for validation when execute is called
        _pendingQuery = kql;

        _logger.LogInformation("KQL query proposed (scope: {Scope}). Awaiting user approval.", scope);

        return JsonSerializer.Serialize(new
        {
            status = "pending_approval",
            message = "Present this query to the user and ask for approval before executing.",
            kql_query = kql,
            explanation,
            estimated_scope = scope
        });
    }

    /// <summary>
    /// Handle execution of an approved KQL query — validate it matches the proposal.
    /// </summary>
    private async Task<string> HandleApprovedExecution(JsonElement args)
    {
        var kql = GetRequired(args, "kql_query");

        // Safety: verify this matches the last proposed query
        if (_pendingQuery == null)
        {
            _logger.LogWarning("Attempted to execute KQL without a pending proposal.");
            return JsonSerializer.Serialize(new
            {
                error = "No query was previously proposed. Use propose_advanced_hunting_query first."
            });
        }

        if (kql.Trim() != _pendingQuery.Trim())
        {
            _logger.LogWarning("Attempted to execute KQL that doesn't match the proposal.");
            return JsonSerializer.Serialize(new
            {
                error = "The query does not match the previously proposed query. Please propose the query again.",
                proposed = _pendingQuery,
                attempted = kql
            });
        }

        // Clear the pending query and execute
        _pendingQuery = null;
        return await _huntingService.RunDynamicQueryAsync(kql);
    }

    // ── Helper methods for argument extraction ──

    private async Task<string> HandleReportGeneration(JsonElement args)
    {
        var reportType = GetRequired(args, "report_type"); // "devices", "sharepoint", or "both"
        var sendEmail = args.TryGetProperty("send_email", out var em) && em.GetBoolean();
        var emailTo = GetOptional(args, "email_to");

        var results = new Dictionary<string, object>();
        var dateStamp = DateTime.UtcNow.ToString("yyyy-MM-dd");

        if (reportType is "devices" or "both")
        {
            _logger.LogInformation("Generating Devices & Vulnerabilities Report on demand");
            var html = await _reportGenerator.GenerateDevicesReportAsync();
            var fileName = $"Devices-Vulnerabilities-Report-{dateStamp}.html";
            var url = await _sharePoint.UploadReportAsync(fileName, html);

            if (sendEmail)
            {
                await _email.SendReportWithAttachmentAsync(
                    "Devices & Vulnerabilities Report", url, html, fileName, emailTo);
            }

            results["devicesReport"] = new { sharePointUrl = url, emailSent = sendEmail };
        }

        if (reportType is "sharepoint" or "both")
        {
            _logger.LogInformation("Generating SharePoint & External Access Report on demand");
            var html = await _reportGenerator.GenerateSharePointReportAsync();
            var fileName = $"SharePoint-External-Access-Report-{dateStamp}.html";
            var url = await _sharePoint.UploadReportAsync(fileName, html);

            if (sendEmail)
            {
                await _email.SendReportWithAttachmentAsync(
                    "SharePoint & External Access Report", url, html, fileName, emailTo);
            }

            results["sharePointReport"] = new { sharePointUrl = url, emailSent = sendEmail };
        }

        return JsonSerializer.Serialize(new
        {
            status = "success",
            message = $"Report(s) generated and uploaded to SharePoint.",
            reports = results
        });
    }

    private static string GetRequired(JsonElement args, string propertyName)
    {
        if (args.TryGetProperty(propertyName, out var value))
        {
            return value.GetString() ?? throw new ArgumentException($"Required parameter '{propertyName}' is null");
        }
        throw new ArgumentException($"Required parameter '{propertyName}' is missing");
    }

    private static string? GetOptional(JsonElement args, string propertyName)
    {
        return args.TryGetProperty(propertyName, out var value) ? value.GetString() : null;
    }

    /// <summary>
    /// Convert severity input like "Critical,High" into KQL IN format: "Critical","High"
    /// </summary>
    private static string FormatSeverityFilter(string severity)
    {
        var parts = severity.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return string.Join(",", parts.Select(p => $"\"{p}\""));
    }
}
