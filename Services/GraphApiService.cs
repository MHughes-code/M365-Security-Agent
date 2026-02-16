using Microsoft.Extensions.Logging;
using SecurityAgent.Config;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Web;

namespace SecurityAgent.Services;

public class GraphApiService
{
    private readonly HttpClient _http;
    private readonly TokenService _tokenService;
    private readonly AgentConfiguration _config;
    private readonly ILogger<GraphApiService> _logger;

    public GraphApiService(
        IHttpClientFactory httpClientFactory,
        TokenService tokenService,
        AgentConfiguration config,
        ILogger<GraphApiService> logger)
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
    /// Look up a user by display name, UPN, or email.
    /// Returns JSON with user ID, UPN, and display name.
    /// </summary>
    public async Task<string> ResolveUserAsync(string searchTerm)
    {
        var client = await GetAuthenticatedClientAsync();

        // Try exact UPN match first, then search by display name
        var encodedSearch = HttpUtility.UrlEncode(searchTerm);
        var url = $"{_config.GraphBaseUrl}/users?" +
                  $"$filter=userPrincipalName eq '{encodedSearch}' " +
                  $"or mail eq '{encodedSearch}' " +
                  $"or displayName eq '{encodedSearch}' " +
                  $"or startswith(displayName,'{encodedSearch}')" +
                  $"&$select=id,userPrincipalName,displayName,mail" +
                  $"&$top=5";

        _logger.LogInformation("Resolving user: {SearchTerm}", searchTerm);

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Graph API error resolving user: {Status} {Content}",
                response.StatusCode, content);
            return JsonSerializer.Serialize(new { error = $"Failed to resolve user: {response.StatusCode}", details = content });
        }

        return content;
    }

    /// <summary>
    /// Get risk detections for a specific user, optionally filtered by date.
    /// </summary>
    public async Task<string> GetRiskDetectionsAsync(string userId, string? since = null)
    {
        var client = await GetAuthenticatedClientAsync();

        var filter = $"userId eq '{userId}'";
        if (!string.IsNullOrEmpty(since))
        {
            // Ensure ISO 8601 format with time component for Graph API
            var sinceDate = since.Contains('T') ? since : $"{since}T00:00:00Z";
            filter += $" and detectedDateTime ge {sinceDate}";
        }

        var url = $"{_config.GraphBaseUrl}/identityProtection/riskDetections?" +
                  $"$filter={HttpUtility.UrlEncode(filter)}" +
                  $"&$orderby=detectedDateTime desc" +
                  $"&$top=50";

        _logger.LogInformation("Getting risk detections for user {UserId} since {Since}",
            userId, since ?? "all time");

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Graph API error getting risk detections: {Status}", response.StatusCode);
            return JsonSerializer.Serialize(new { error = $"Failed to get risk detections: {response.StatusCode}", details = content });
        }

        return content;
    }

    /// <summary>
    /// Get sign-in logs flagged as risky for a user.
    /// </summary>
    public async Task<string> GetRiskySignInsAsync(string userId, string? since = null, string? riskLevel = null)
    {
        var client = await GetAuthenticatedClientAsync();

        var filter = $"userId eq '{userId}'";
        if (!string.IsNullOrEmpty(since))
        {
            var sinceDate = since.Contains('T') ? since : $"{since}T00:00:00Z";
            filter += $" and createdDateTime ge {sinceDate}";
        }
        // Note: riskLevelDuringSignIn filter added only if explicitly requested
        // The ne 'none' filter causes 400 errors on some tenants
        if (!string.IsNullOrEmpty(riskLevel))
        {
            filter += $" and riskLevelDuringSignIn eq '{riskLevel}'";
        }

        var url = $"{_config.GraphBaseUrl}/auditLogs/signIns?" +
                  $"$filter={HttpUtility.UrlEncode(filter)}" +
                  $"&$top=50" +
                  $"&$select=id,createdDateTime,userPrincipalName,ipAddress,location," +
                  $"riskLevelDuringSignIn,riskState,riskDetail,clientAppUsed," +
                  $"deviceDetail,conditionalAccessStatus,status";

        _logger.LogInformation("Getting risky sign-ins for user {UserId}", userId);
        _logger.LogDebug("Sign-in query URL: {Url}", url);

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Graph API error getting risky sign-ins: {Status} {Content}",
                response.StatusCode, content);
            return JsonSerializer.Serialize(new { error = $"Failed to get risky sign-ins: {response.StatusCode}", details = content });
        }

        return content;
    }

    /// <summary>
    /// Get security incidents from Microsoft 365 Defender via Graph Security API.
    /// </summary>
    public async Task<string> GetIncidentsAsync(string? severity = null, string? status = null, string? since = null)
    {
        var client = await GetAuthenticatedClientAsync();

        var filters = new List<string>();
        if (!string.IsNullOrEmpty(severity))
            filters.Add($"severity eq '{severity}'");
        if (!string.IsNullOrEmpty(status))
            filters.Add($"status eq '{status}'");
        if (!string.IsNullOrEmpty(since))
        {
            var sinceDate = since.Contains('T') ? since : $"{since}T00:00:00Z";
            filters.Add($"createdDateTime ge {sinceDate}");
        }

        var filterQuery = filters.Count > 0 ? $"?$filter={string.Join(" and ", filters)}" : "";
        var url = $"{_config.GraphBaseUrl}/security/incidents{filterQuery}";

        _logger.LogInformation("Getting incidents (severity: {Severity}, status: {Status})",
            severity ?? "all", status ?? "all");

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Graph API error getting incidents: {Status} {Content}",
                response.StatusCode, content);
            return JsonSerializer.Serialize(new { error = $"Failed to get incidents: {response.StatusCode}", details = content });
        }

        return content;
    }

    // ═══════════════════════════════════════════
    // SHAREPOINT / GUEST ACCESS
    // ═══════════════════════════════════════════

    /// <summary>
    /// Get all guest/external users in the tenant.
    /// Returns display name, email, creation date, and sign-in activity.
    /// </summary>
    public async Task<string> GetGuestUsersAsync()
    {
        var client = await GetAuthenticatedClientAsync();

        var url = $"{_config.GraphBaseUrl}/users?" +
                  $"$filter=userType eq 'Guest'" +
                  $"&$select=id,displayName,mail,userPrincipalName,createdDateTime," +
                  $"externalUserState,externalUserStateChangeDateTime,accountEnabled" +
                  $"&$top=999";

        _logger.LogInformation("Getting guest users");

        var allGuests = new List<JsonElement>();
        var nextUrl = url;

        while (!string.IsNullOrEmpty(nextUrl))
        {
            var response = await client.GetAsync(nextUrl);
            var content = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Graph API error getting guest users: {Status} {Content}",
                    response.StatusCode, content);
                return JsonSerializer.Serialize(new { error = $"Failed to get guest users: {response.StatusCode}", details = content });
            }

            using var doc = JsonDocument.Parse(content);
            if (doc.RootElement.TryGetProperty("value", out var values))
            {
                foreach (var item in values.EnumerateArray())
                    allGuests.Add(item.Clone());
            }

            nextUrl = doc.RootElement.TryGetProperty("@odata.nextLink", out var next) ? next.GetString() : null;
        }

        return JsonSerializer.Serialize(new { value = allGuests, totalCount = allGuests.Count });
    }

    /// <summary>
    /// Get details on a specific guest user including sign-in activity.
    /// </summary>
    public async Task<string> GetGuestUserDetailsAsync(string guestId)
    {
        var client = await GetAuthenticatedClientAsync();

        var url = $"{_config.GraphBaseUrl}/users/{guestId}?" +
                  $"$select=id,displayName,mail,userPrincipalName,createdDateTime," +
                  $"externalUserState,externalUserStateChangeDateTime,accountEnabled," +
                  $"signInActivity,companyName,jobTitle";

        _logger.LogInformation("Getting guest user details: {GuestId}", guestId);

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Graph API error getting guest details: {Status} {Content}",
                response.StatusCode, content);
            return JsonSerializer.Serialize(new { error = $"Failed to get guest user details: {response.StatusCode}", details = content });
        }

        return content;
    }
}
