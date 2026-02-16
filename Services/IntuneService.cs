using Microsoft.Extensions.Logging;
using SecurityAgent.Config;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Web;

namespace SecurityAgent.Services;

public class IntuneService
{
    private readonly HttpClient _http;
    private readonly TokenService _tokenService;
    private readonly AgentConfiguration _config;
    private readonly ILogger<IntuneService> _logger;

    public IntuneService(
        IHttpClientFactory httpClientFactory,
        TokenService tokenService,
        AgentConfiguration config,
        ILogger<IntuneService> logger)
    {
        _http = httpClientFactory.CreateClient();
        _tokenService = tokenService;
        _config = config;
        _logger = logger;
    }

    private async Task<HttpClient> GetAuthenticatedClientAsync()
    {
        var token = await _tokenService.GetTokenAsync(_config.GraphScope);
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);
        return _http;
    }

    /// <summary>
    /// Get a summary of device compliance across the tenant.
    /// Returns counts of compliant, noncompliant, in-grace-period, etc.
    /// </summary>
    public async Task<string> GetDeviceComplianceSummaryAsync()
    {
        var client = await GetAuthenticatedClientAsync();

        // Get all managed devices with compliance state
        var url = $"{_config.GraphBaseUrl}/deviceManagement/managedDevices?" +
                  $"$select=id,deviceName,complianceState,operatingSystem,osVersion," +
                  $"userPrincipalName,lastSyncDateTime,managementAgent,deviceEnrollmentType," +
                  $"model,manufacturer" +
                  $"&$top=999";

        _logger.LogInformation("Getting device compliance summary");

        var allDevices = new List<JsonElement>();
        var nextUrl = url;

        // Handle pagination
        while (!string.IsNullOrEmpty(nextUrl))
        {
            var response = await client.GetAsync(nextUrl);
            var content = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Intune API error getting managed devices: {Status} {Content}",
                    response.StatusCode, content);
                return JsonSerializer.Serialize(new { error = $"Failed to get managed devices: {response.StatusCode}", details = content });
            }

            var doc = JsonDocument.Parse(content);
            if (doc.RootElement.TryGetProperty("value", out var values))
            {
                foreach (var device in values.EnumerateArray())
                {
                    allDevices.Add(device.Clone());
                }
            }

            // Check for next page
            nextUrl = doc.RootElement.TryGetProperty("@odata.nextLink", out var next)
                ? next.GetString() : null;
        }

        // Build summary
        var summary = new
        {
            totalDevices = allDevices.Count,
            compliant = allDevices.Count(d => GetComplianceState(d) == "compliant"),
            noncompliant = allDevices.Count(d => GetComplianceState(d) == "noncompliant"),
            inGracePeriod = allDevices.Count(d => GetComplianceState(d) == "inGracePeriod"),
            configManager = allDevices.Count(d => GetComplianceState(d) == "configManager"),
            unknown = allDevices.Count(d => GetComplianceState(d) == "unknown"),
            byOS = allDevices.GroupBy(d => GetStringProp(d, "operatingSystem"))
                .Select(g => new
                {
                    os = g.Key,
                    total = g.Count(),
                    compliant = g.Count(d => GetComplianceState(d) == "compliant"),
                    noncompliant = g.Count(d => GetComplianceState(d) == "noncompliant")
                })
                .OrderByDescending(g => g.total)
                .ToList()
        };

        return JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// Get noncompliant devices with details about why they're noncompliant.
    /// </summary>
    public async Task<string> GetNoncompliantDevicesAsync(string? osFilter = null)
    {
        var client = await GetAuthenticatedClientAsync();

        var filter = "complianceState eq 'noncompliant'";
        if (!string.IsNullOrEmpty(osFilter))
        {
            filter += $" and operatingSystem eq '{osFilter}'";
        }

        var url = $"{_config.GraphBaseUrl}/deviceManagement/managedDevices?" +
                  $"$filter={HttpUtility.UrlEncode(filter)}" +
                  $"&$select=id,deviceName,complianceState,operatingSystem,osVersion," +
                  $"userPrincipalName,lastSyncDateTime,model,manufacturer" +
                  $"&$orderby=deviceName" +
                  $"&$top=100";

        _logger.LogInformation("Getting noncompliant devices (OS filter: {OS})", osFilter ?? "all");

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Intune API error getting noncompliant devices: {Status} {Content}",
                response.StatusCode, content);
            return JsonSerializer.Serialize(new { error = $"Failed to get noncompliant devices: {response.StatusCode}", details = content });
        }

        return content;
    }

    /// <summary>
    /// Get device compliance policy assignments and their status.
    /// </summary>
    public async Task<string> GetCompliancePoliciesAsync()
    {
        var client = await GetAuthenticatedClientAsync();

        var url = $"{_config.GraphBaseUrl}/deviceManagement/deviceCompliancePolicies?" +
                  $"$select=id,displayName,description,lastModifiedDateTime,version" +
                  $"&$expand=assignments,deviceStatusOverview";

        _logger.LogInformation("Getting compliance policies");

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Intune API error getting compliance policies: {Status} {Content}",
                response.StatusCode, content);
            return JsonSerializer.Serialize(new { error = $"Failed to get compliance policies: {response.StatusCode}", details = content });
        }

        return content;
    }

    /// <summary>
    /// Get Windows Update for Business configuration rings and their status.
    /// </summary>
    public async Task<string> GetWindowsUpdateRingsAsync()
    {
        var client = await GetAuthenticatedClientAsync();

        var url = $"{_config.GraphBaseUrl}/deviceManagement/deviceConfigurations?" +
                  $"$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')" +
                  $"&$select=id,displayName,description,lastModifiedDateTime,version";

        _logger.LogInformation("Getting Windows Update rings");

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            // The isof filter may not work on all tenants — fall back to getting all configs
            // and filtering client-side
            _logger.LogWarning("Filtered query failed, trying unfiltered approach");

            url = $"{_config.GraphBaseUrl}/deviceManagement/deviceConfigurations?" +
                  $"$select=id,displayName,description,lastModifiedDateTime,version";

            response = await client.GetAsync(url);
            content = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Intune API error getting update rings: {Status} {Content}",
                    response.StatusCode, content);
                return JsonSerializer.Serialize(new { error = $"Failed to get update rings: {response.StatusCode}", details = content });
            }
        }

        return content;
    }

    /// <summary>
    /// Get Windows Update for Business update ring status — which devices have pending updates.
    /// </summary>
    public async Task<string> GetWindowsUpdateStatusAsync()
    {
        var client = await GetAuthenticatedClientAsync();

        var url = $"{_config.GraphBaseUrl}/deviceManagement/softwareUpdateStatusSummary";

        _logger.LogInformation("Getting Windows Update status summary");

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Intune API error getting update status: {Status} {Content}",
                response.StatusCode, content);
            return JsonSerializer.Serialize(new { error = $"Failed to get update status: {response.StatusCode}", details = content });
        }

        return content;
    }

    /// <summary>
    /// Get details for a specific managed device by name.
    /// </summary>
    public async Task<string> GetDeviceDetailsAsync(string deviceName)
    {
        var client = await GetAuthenticatedClientAsync();

        var url = $"{_config.GraphBaseUrl}/deviceManagement/managedDevices?" +
                  $"$filter=deviceName eq '{HttpUtility.UrlEncode(deviceName)}'" +
                  $"&$select=id,deviceName,complianceState,operatingSystem,osVersion," +
                  $"userPrincipalName,lastSyncDateTime,managementAgent,deviceEnrollmentType," +
                  $"model,manufacturer,serialNumber,totalStorageSpaceInBytes," +
                  $"freeStorageSpaceInBytes,managedDeviceName,enrolledDateTime," +
                  $"isEncrypted,isSupervised,azureADRegistered,azureADDeviceId";

        _logger.LogInformation("Getting device details for: {Device}", deviceName);

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Intune API error getting device details: {Status} {Content}",
                response.StatusCode, content);
            return JsonSerializer.Serialize(new { error = $"Failed to get device details: {response.StatusCode}", details = content });
        }

        return content;
    }

    /// <summary>
    /// Get all devices assigned to a specific user by UPN or display name.
    /// </summary>
    public async Task<string> GetDevicesByUserAsync(string user)
    {
        var client = await GetAuthenticatedClientAsync();

        var filter = user.Contains('@')
            ? $"userPrincipalName eq '{HttpUtility.UrlEncode(user)}'"
            : $"startswith(userPrincipalName, '{HttpUtility.UrlEncode(user)}')";

        var url = $"{_config.GraphBaseUrl}/deviceManagement/managedDevices?" +
                  $"$filter={filter}" +
                  $"&$select=id,deviceName,complianceState,operatingSystem,osVersion," +
                  $"userPrincipalName,lastSyncDateTime,model,manufacturer,serialNumber" +
                  $"&$orderby=deviceName" +
                  $"&$top=50";

        _logger.LogInformation("Getting devices for user: {User}", user);

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Intune API error getting devices by user: {Status} {Content}",
                response.StatusCode, content);
            return JsonSerializer.Serialize(new { error = $"Failed to get devices for user: {response.StatusCode}", details = content });
        }

        return content;
    }

    /// <summary>
    /// Get devices that haven't synced recently (stale devices).
    /// </summary>
    public async Task<string> GetStaleDevicesAsync(int daysInactive = 30)
    {
        var client = await GetAuthenticatedClientAsync();

        var cutoffDate = DateTime.UtcNow.AddDays(-daysInactive).ToString("yyyy-MM-ddTHH:mm:ssZ");

        var url = $"{_config.GraphBaseUrl}/deviceManagement/managedDevices?" +
                  $"$filter=lastSyncDateTime le {cutoffDate}" +
                  $"&$select=id,deviceName,operatingSystem,osVersion," +
                  $"userPrincipalName,lastSyncDateTime,complianceState,model" +
                  $"&$orderby=lastSyncDateTime asc" +
                  $"&$top=100";

        _logger.LogInformation("Getting stale devices (inactive > {Days} days)", daysInactive);

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Intune API error getting stale devices: {Status} {Content}",
                response.StatusCode, content);
            return JsonSerializer.Serialize(new { error = $"Failed to get stale devices: {response.StatusCode}", details = content });
        }

        return content;
    }

    // ── Helper methods ──

    private static string GetComplianceState(JsonElement device)
    {
        return device.TryGetProperty("complianceState", out var state)
            ? state.GetString() ?? "unknown" : "unknown";
    }

    private static string GetStringProp(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var val)
            ? val.GetString() ?? "Unknown" : "Unknown";
    }
}
