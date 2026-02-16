using Microsoft.Extensions.Logging;
using SecurityAgent.Config;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace SecurityAgent.Services;

public class AdvancedHuntingService
{
    private readonly HttpClient _http;
    private readonly TokenService _tokenService;
    private readonly AgentConfiguration _config;
    private readonly ILogger<AdvancedHuntingService> _logger;

    // KQL Templates for Tier 2 (auto-execute)
    private static readonly Dictionary<string, string> KqlTemplates = new()
    {
        ["search_emails"] = """
            EmailEvents
            | where Timestamp between (datetime({start_date}) .. datetime({end_date}))
            | where SenderMailFromAddress =~ "{email_address}" or RecipientEmailAddress =~ "{email_address}"
            | project Timestamp, SenderMailFromAddress, RecipientEmailAddress,
                      Subject, DeliveryAction, DeliveryLocation, NetworkMessageId
            | order by Timestamp desc
            | take 100
            """,

        ["search_emails_by_subject"] = """
            EmailEvents
            | where Timestamp between (datetime({start_date}) .. datetime({end_date}))
            | where Subject contains "{keyword}"
            | project Timestamp, SenderMailFromAddress, RecipientEmailAddress,
                      Subject, DeliveryAction, DeliveryLocation, NetworkMessageId
            | order by Timestamp desc
            | take 100
            """,

        ["search_sign_ins"] = """
            IdentityLogonEvents
            | where Timestamp between (datetime({start_date}) .. datetime({end_date}))
            | where AccountUpn =~ "{user_upn}"
            | project Timestamp, AccountUpn, LogonType, ActionType,
                      IPAddress, Location, DeviceName, Application
            | order by Timestamp desc
            | take 100
            """,

        ["search_device_activity"] = """
            union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents
            | where Timestamp between (datetime({start_date}) .. datetime({end_date}))
            | where DeviceName =~ "{device_name}"
            | project Timestamp, DeviceName, ActionType,
                      FileName, ProcessCommandLine, RemoteUrl, RemoteIP
            | order by Timestamp desc
            | take 200
            """,

        ["search_email_urls"] = """
            EmailUrlInfo
            | join kind=inner EmailEvents on NetworkMessageId
            | where Timestamp between (datetime({start_date}) .. datetime({end_date}))
            | where Url contains "{url_pattern}" or RecipientEmailAddress =~ "{email_address}"
            | project Timestamp, SenderMailFromAddress, RecipientEmailAddress,
                      Subject, Url, UrlDomain
            | order by Timestamp desc
            | take 100
            """,

        ["search_cloud_activity"] = """
            CloudAppEvents
            | where Timestamp between (datetime({start_date}) .. datetime({end_date}))
            | where AccountDisplayName =~ "{user_name}" 
                or AccountId =~ "{user_name}"
                or AccountObjectId =~ "{user_name}"
                or tostring(RawEventData.UserId) =~ "{user_name}"
            | project Timestamp, AccountDisplayName, AccountId, AccountObjectId, ActionType,
                      Application, ObjectName, IPAddress, City, CountryCode
            | order by Timestamp desc
            | take 100
            """,

        ["search_device_vulnerabilities"] = """
            DeviceTvmSoftwareVulnerabilities
            | where VulnerabilitySeverityLevel in ({severity_filter})
            | join kind=leftouter DeviceTvmSoftwareVulnerabilitiesKB on CveId
            | project DeviceName, DeviceId, CveId, VulnerabilitySeverityLevel,
                      SoftwareName, SoftwareVersion, CvssScore,
                      RecommendedSecurityUpdate, RecommendedSecurityUpdateId
            | summarize CVEs = make_set(CveId),
                        Software = make_set(SoftwareName),
                        MaxCVSS = max(CvssScore),
                        TotalVulns = count()
                        by DeviceName, DeviceId
            | order by MaxCVSS desc, TotalVulns desc
            | take 100
            """,

        ["search_vulnerability_summary"] = """
            DeviceTvmSoftwareVulnerabilities
            | join kind=leftouter DeviceTvmSoftwareVulnerabilitiesKB on CveId
            | summarize 
                TotalVulnerabilities = dcount(CveId),
                CriticalVulnerabilities = dcountif(CveId, VulnerabilitySeverityLevel == "Critical"),
                HighVulnerabilities = dcountif(CveId, VulnerabilitySeverityLevel == "High"),
                MediumVulnerabilities = dcountif(CveId, VulnerabilitySeverityLevel == "Medium"),
                LowVulnerabilities = dcountif(CveId, VulnerabilitySeverityLevel == "Low"),
                ExploitableVulnerabilities = dcountif(CveId, IsExploitAvailable == 1),
                ZeroDayVulnerabilities = dcountif(CveId, CveTags has "ZeroDay"),
                VulnsWithSecurityUpdate = dcountif(CveId, isnotempty(RecommendedSecurityUpdate)),
                VulnsWithoutSecurityUpdate = dcountif(CveId, isempty(RecommendedSecurityUpdate)),
                AffectedDevices = dcount(DeviceId)
            """,

        ["search_device_vulnerabilities_detail"] = """
            DeviceTvmSoftwareVulnerabilities
            | where DeviceName =~ "{device_name}"
            | where VulnerabilitySeverityLevel in ({severity_filter})
            | join kind=leftouter DeviceTvmSoftwareVulnerabilitiesKB on CveId
            | project DeviceName, CveId, VulnerabilitySeverityLevel,
                      SoftwareName, SoftwareVersion, CvssScore,
                      RecommendedSecurityUpdate
            | order by CvssScore desc
            | take 200
            """,

        // ── SharePoint / External Sharing ──

        ["search_external_sharing"] = """
            CloudAppEvents
            | where Timestamp between (datetime({start_date}) .. datetime({end_date}))
            | where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
            | where ActionType in ("SharingLinkCreated", "SharingInvitationCreated", "AnonymousLinkCreated",
                                    "AddedToSharingLink", "SharingSet", "SecureLinkCreated")
            | extend SharedWith = tostring(RawEventData.TargetUserOrGroupName)
            | extend ItemName = tostring(RawEventData.ObjectId)
            | extend SiteUrl = tostring(RawEventData.SiteUrl)
            | extend ShareType = tostring(RawEventData.EventData)
            | where SharedWith !endswith "yourdomain.com" 
                and SharedWith != "" 
                and SharedWith !startswith "Everyone"
            | project Timestamp, AccountDisplayName, ActionType, ItemName, 
                      SharedWith, SiteUrl, IPAddress, CountryCode
            | order by Timestamp desc
            | take 200
            """,

        ["search_user_sharing"] = """
            CloudAppEvents
            | where Timestamp between (datetime({start_date}) .. datetime({end_date}))
            | where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
            | where ActionType in ("SharingLinkCreated", "SharingInvitationCreated", "AnonymousLinkCreated",
                                    "AddedToSharingLink", "SharingSet", "SecureLinkCreated")
            | where AccountDisplayName =~ "{user_name}" 
                or AccountId =~ "{user_name}"
                or AccountObjectId =~ "{user_name}"
            | extend SharedWith = tostring(RawEventData.TargetUserOrGroupName)
            | extend ItemName = tostring(RawEventData.ObjectId)
            | extend SiteUrl = tostring(RawEventData.SiteUrl)
            | project Timestamp, AccountDisplayName, ActionType, ItemName,
                      SharedWith, SiteUrl, IPAddress
            | order by Timestamp desc
            | take 100
            """,

        ["search_guest_activity"] = """
            CloudAppEvents
            | where Timestamp between (datetime({start_date}) .. datetime({end_date}))
            | where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
            | where AccountId =~ "{guest_email}" 
                or AccountDisplayName =~ "{guest_name}"
            | extend ItemName = tostring(RawEventData.ObjectId)
            | extend SiteUrl = tostring(RawEventData.SiteUrl)
            | project Timestamp, AccountDisplayName, AccountId, ActionType,
                      ItemName, SiteUrl, Application, IPAddress, CountryCode
            | order by Timestamp desc
            | take 200
            """
    };

    public AdvancedHuntingService(
        IHttpClientFactory httpClientFactory,
        TokenService tokenService,
        AgentConfiguration config,
        ILogger<AdvancedHuntingService> logger)
    {
        _http = httpClientFactory.CreateClient();
        _tokenService = tokenService;
        _config = config;
        _logger = logger;
    }

    /// <summary>
    /// Execute a Tier 2 template-based hunting query.
    /// Substitutes parameters into the template and runs it.
    /// </summary>
    public async Task<string> RunTemplateQueryAsync(string templateName, Dictionary<string, string> parameters)
    {
        if (!KqlTemplates.TryGetValue(templateName, out var template))
        {
            return JsonSerializer.Serialize(new { error = $"Unknown template: {templateName}" });
        }

        // Substitute parameters — sanitize to prevent KQL injection
        var kql = template;
        foreach (var (key, value) in parameters)
        {
            // severity_filter is pre-formatted by our code with quotes for KQL IN operator
            // Don't sanitize it or the quotes get stripped
            var substitution = key == "severity_filter" ? value : SanitizeKqlParameter(value);
            kql = kql.Replace($"{{{key}}}", substitution);
        }

        _logger.LogInformation("Running template hunting query: {Template} with params: {Params}",
            templateName, JsonSerializer.Serialize(parameters));

        return await ExecuteKqlAsync(kql);
    }

    /// <summary>
    /// Execute a Tier 3 dynamic KQL query (after human approval).
    /// </summary>
    public async Task<string> RunDynamicQueryAsync(string kql)
    {
        _logger.LogWarning("Executing DYNAMIC hunting query (user-approved): {Query}",
            kql.Length > 200 ? kql[..200] + "..." : kql);

        return await ExecuteKqlAsync(kql);
    }

    /// <summary>
    /// Execute a KQL query against the Advanced Hunting API.
    /// Uses the Microsoft Graph Security API endpoint.
    /// </summary>
    private async Task<string> ExecuteKqlAsync(string kql)
    {
        var token = await _tokenService.GetTokenAsync(_config.GraphScope);
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        var url = $"{_config.GraphBaseUrl}/security/runHuntingQuery";
        var body = JsonSerializer.Serialize(new { Query = kql });

        _logger.LogDebug("Executing KQL: {Query}", kql);

        var response = await _http.PostAsync(url,
            new StringContent(body, Encoding.UTF8, "application/json"));

        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Advanced Hunting API error: {Status} {Content}",
                response.StatusCode, content);
            return JsonSerializer.Serialize(new
            {
                error = $"Hunting query failed: {response.StatusCode}",
                details = content,
                query = kql
            });
        }

        // Trim results if too large (to stay within token limits)
        content = TrimResultsIfNeeded(content);

        return content;
    }

    /// <summary>
    /// Sanitize user-provided values before inserting into KQL templates.
    /// Prevents KQL injection by escaping dangerous characters.
    /// </summary>
    private static string SanitizeKqlParameter(string value)
    {
        // Remove KQL operators and dangerous characters
        return value
            .Replace("'", "''")   // Escape single quotes
            .Replace("\"", "")    // Remove double quotes
            .Replace(";", "")     // Remove statement terminators
            .Replace("//", "")    // Remove comments
            .Replace("/*", "")    // Remove block comments
            .Replace("*/", "")
            .Trim();
    }

    /// <summary>
    /// Trim large result sets to avoid blowing the context window.
    /// </summary>
    private string TrimResultsIfNeeded(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("Results", out var results))
                return json;

            var resultArray = results.EnumerateArray().ToList();
            if (resultArray.Count <= _config.MaxHuntingResults)
                return json;

            var trimmed = resultArray.Take(_config.MaxHuntingResults).ToList();
            return JsonSerializer.Serialize(new
            {
                Results = trimmed,
                TotalResults = resultArray.Count,
                Trimmed = true,
                Message = $"Results trimmed to {_config.MaxHuntingResults} of {resultArray.Count} total. Refine your query for more specific results."
            });
        }
        catch
        {
            return json;
        }
    }
}
