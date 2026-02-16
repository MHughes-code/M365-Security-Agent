using Microsoft.Extensions.Logging;
using SecurityAgent.Config;
using System.Net.Http.Headers;
using System.Text.Json;

namespace SecurityAgent.Services;

public class DefenderApiService
{
    private readonly HttpClient _http;
    private readonly TokenService _tokenService;
    private readonly AgentConfiguration _config;
    private readonly ILogger<DefenderApiService> _logger;

    public DefenderApiService(
        IHttpClientFactory httpClientFactory,
        TokenService tokenService,
        AgentConfiguration config,
        ILogger<DefenderApiService> logger)
    {
        _http = httpClientFactory.CreateClient();
        _tokenService = tokenService;
        _config = config;
        _logger = logger;
    }

    private async Task<HttpClient> GetAuthenticatedClientAsync()
    {
        var token = await _tokenService.GetTokenAsync(_config.DefenderScope);
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);
        return _http;
    }

    /// <summary>
    /// Get machines from Defender for Endpoint, optionally filtered by type and exposure.
    /// </summary>
    public async Task<string> GetMachinesAsync(string? deviceType = null, string? minExposure = null)
    {
        var client = await GetAuthenticatedClientAsync();

        var filters = new List<string>();
        if (!string.IsNullOrEmpty(deviceType))
        {
            // Defender uses computerDnsName patterns or osPlatform, but
            // deviceType isn't a direct filter — we'll filter client-side
        }

        var filterQuery = filters.Count > 0 ? $"?$filter={string.Join(" and ", filters)}" : "";
        var url = $"{_config.DefenderBaseUrl}/machines{filterQuery}";

        _logger.LogInformation("Getting machines from Defender (type: {Type}, exposure: {Exposure})",
            deviceType ?? "all", minExposure ?? "all");

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Defender API error getting machines: {Status}", response.StatusCode);
            return JsonSerializer.Serialize(new { error = $"Failed to get machines: {response.StatusCode}", details = content });
        }

        // If device type filter requested, apply client-side filtering
        if (!string.IsNullOrEmpty(deviceType) || !string.IsNullOrEmpty(minExposure))
        {
            content = FilterMachines(content, deviceType, minExposure);
        }

        return content;
    }

    private string FilterMachines(string json, string? deviceType, string? minExposure)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var machines = doc.RootElement.GetProperty("value").EnumerateArray();

            var exposureLevels = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                ["None"] = 0, ["Low"] = 1, ["Medium"] = 2, ["High"] = 3
            };

            var minExpLevel = minExposure != null && exposureLevels.ContainsKey(minExposure)
                ? exposureLevels[minExposure]
                : 0;

            var filtered = machines.Where(m =>
            {
                // Filter by device type (check machineTags or computerDnsName patterns)
                if (!string.IsNullOrEmpty(deviceType))
                {
                    var platform = m.TryGetProperty("osPlatform", out var p) ? p.GetString() ?? "" : "";
                    var name = m.TryGetProperty("computerDnsName", out var n) ? n.GetString() ?? "" : "";
                    // Basic heuristic — you may want to refine based on your naming conventions
                    if (!name.Contains(deviceType, StringComparison.OrdinalIgnoreCase) &&
                        !platform.Contains(deviceType, StringComparison.OrdinalIgnoreCase))
                    {
                        // Check machineTags
                        if (m.TryGetProperty("machineTags", out var tags))
                        {
                            var tagMatch = tags.EnumerateArray()
                                .Any(t => t.GetString()?.Contains(deviceType, StringComparison.OrdinalIgnoreCase) == true);
                            if (!tagMatch) return false;
                        }
                        else return false;
                    }
                }

                // Filter by exposure level
                if (minExposure != null)
                {
                    var level = m.TryGetProperty("exposureLevel", out var e) ? e.GetString() ?? "None" : "None";
                    if (exposureLevels.TryGetValue(level, out var machineLevel))
                    {
                        if (machineLevel < minExpLevel) return false;
                    }
                }

                return true;
            }).ToList();

            return JsonSerializer.Serialize(new { value = filtered, filteredCount = filtered.Count });
        }
        catch
        {
            return json; // Return unfiltered if parsing fails
        }
    }

    /// <summary>
    /// Get vulnerabilities for a specific machine.
    /// </summary>
    public async Task<string> GetMachineVulnerabilitiesAsync(string machineId, string? minSeverity = null)
    {
        var client = await GetAuthenticatedClientAsync();

        var url = $"{_config.DefenderBaseUrl}/machines/{machineId}/vulnerabilities";

        _logger.LogInformation("Getting vulnerabilities for machine {MachineId}", machineId);

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Defender API error getting vulnerabilities: {Status}", response.StatusCode);
            return JsonSerializer.Serialize(new { error = $"Failed to get vulnerabilities: {response.StatusCode}", details = content });
        }

        // Filter by severity if requested
        if (!string.IsNullOrEmpty(minSeverity))
        {
            content = FilterBySeverity(content, minSeverity);
        }

        return content;
    }

    private string FilterBySeverity(string json, string minSeverity)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var items = doc.RootElement.GetProperty("value").EnumerateArray();

            var severityLevels = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                ["None"] = 0, ["Low"] = 1, ["Medium"] = 2, ["High"] = 3, ["Critical"] = 4
            };

            var minLevel = severityLevels.TryGetValue(minSeverity, out var l) ? l : 0;

            var filtered = items.Where(v =>
            {
                var severity = v.TryGetProperty("severity", out var s) ? s.GetString() ?? "None" : "None";
                return severityLevels.TryGetValue(severity, out var vLevel) && vLevel >= minLevel;
            }).ToList();

            return JsonSerializer.Serialize(new { value = filtered, filteredCount = filtered.Count });
        }
        catch
        {
            return json;
        }
    }

    /// <summary>
    /// Get security recommendations, optionally filtered by CVE or software.
    /// </summary>
    public async Task<string> GetRecommendationsAsync(string? relatedCve = null, string? relatedSoftware = null)
    {
        var client = await GetAuthenticatedClientAsync();

        var url = $"{_config.DefenderBaseUrl}/recommendations";

        _logger.LogInformation("Getting security recommendations (CVE: {Cve}, Software: {Software})",
            relatedCve ?? "all", relatedSoftware ?? "all");

        var response = await client.GetAsync(url);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("Defender API error getting recommendations: {Status}", response.StatusCode);
            return JsonSerializer.Serialize(new { error = $"Failed to get recommendations: {response.StatusCode}", details = content });
        }

        // Filter client-side if CVE or software specified
        if (!string.IsNullOrEmpty(relatedCve) || !string.IsNullOrEmpty(relatedSoftware))
        {
            try
            {
                using var doc = JsonDocument.Parse(content);
                var recs = doc.RootElement.GetProperty("value").EnumerateArray();

                var filtered = recs.Where(r =>
                {
                    if (!string.IsNullOrEmpty(relatedCve))
                    {
                        var weaknesses = r.TryGetProperty("weaknesses", out var w) ? w.ToString() : "";
                        if (!weaknesses.Contains(relatedCve, StringComparison.OrdinalIgnoreCase))
                            return false;
                    }
                    if (!string.IsNullOrEmpty(relatedSoftware))
                    {
                        var product = r.TryGetProperty("productName", out var p) ? p.GetString() ?? "" : "";
                        var vendor = r.TryGetProperty("vendor", out var v) ? v.GetString() ?? "" : "";
                        if (!product.Contains(relatedSoftware, StringComparison.OrdinalIgnoreCase) &&
                            !vendor.Contains(relatedSoftware, StringComparison.OrdinalIgnoreCase))
                            return false;
                    }
                    return true;
                }).ToList();

                content = JsonSerializer.Serialize(new { value = filtered, filteredCount = filtered.Count });
            }
            catch { /* Return unfiltered */ }
        }

        return content;
    }

}
