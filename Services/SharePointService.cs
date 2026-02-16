using Microsoft.Extensions.Logging;
using SecurityAgent.Config;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace SecurityAgent.Services;

public class SharePointService
{
    private readonly HttpClient _http;
    private readonly TokenService _tokenService;
    private readonly AgentConfiguration _config;
    private readonly ILogger<SharePointService> _logger;

    public SharePointService(
        IHttpClientFactory httpClientFactory,
        TokenService tokenService,
        AgentConfiguration config,
        ILogger<SharePointService> logger)
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
    /// Upload an HTML report to a SharePoint document library.
    /// Creates the folder if it doesn't exist.
    /// Returns the web URL of the uploaded file.
    /// </summary>
    public async Task<string> UploadReportAsync(string fileName, string htmlContent)
    {
        if (string.IsNullOrEmpty(_config.ReportSharePointSiteId))
        {
            _logger.LogWarning("ReportSharePointSiteId is not configured, skipping SharePoint upload");
            return "";
        }

        var client = await GetAuthenticatedClientAsync();
        var siteId = _config.ReportSharePointSiteId;
        var libraryName = _config.ReportDocumentLibrary;

        _logger.LogInformation("Uploading report {FileName} to SharePoint site {SiteId}/{Library}",
            fileName, siteId, libraryName);

        try
        {
            // Get the drive (document library) for the site
            // First try to find the library by name
            var drivesUrl = $"{_config.GraphBaseUrl}/sites/{siteId}/drives";
            var drivesResponse = await client.GetAsync(drivesUrl);
            var drivesContent = await drivesResponse.Content.ReadAsStringAsync();

            if (!drivesResponse.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to list drives: {Status} {Content}",
                    drivesResponse.StatusCode, drivesContent);
                return $"Error: Failed to list SharePoint drives: {drivesResponse.StatusCode}";
            }

            string? driveId = null;
            using (var doc = JsonDocument.Parse(drivesContent))
            {
                if (doc.RootElement.TryGetProperty("value", out var drives))
                {
                    foreach (var drive in drives.EnumerateArray())
                    {
                        var name = drive.TryGetProperty("name", out var n) ? n.GetString() : "";
                        if (name?.Equals(libraryName, StringComparison.OrdinalIgnoreCase) == true)
                        {
                            driveId = drive.GetProperty("id").GetString();
                            break;
                        }
                    }

                    // If not found by name, use the default document library
                    if (driveId == null)
                    {
                        foreach (var drive in drives.EnumerateArray())
                        {
                            var driveType = drive.TryGetProperty("driveType", out var dt) ? dt.GetString() : "";
                            if (driveType == "documentLibrary")
                            {
                                driveId = drive.GetProperty("id").GetString();
                                _logger.LogWarning("Library '{Library}' not found, using default: {DriveId}",
                                    libraryName, driveId);
                                break;
                            }
                        }
                    }
                }
            }

            if (string.IsNullOrEmpty(driveId))
            {
                return "Error: No document library found on SharePoint site";
            }

            // Upload the file — use simple upload for files < 4MB
            var bytes = Encoding.UTF8.GetBytes(htmlContent);
            var folderPath = _config.ReportFolderPath.TrimStart('/').TrimEnd('/');
            var uploadUrl = $"{_config.GraphBaseUrl}/drives/{driveId}/root:/{folderPath}/{fileName}:/content";

            var request = new HttpRequestMessage(HttpMethod.Put, uploadUrl)
            {
                Content = new ByteArrayContent(bytes)
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("text/html");

            var uploadResponse = await client.SendAsync(request);
            var uploadContent = await uploadResponse.Content.ReadAsStringAsync();

            if (!uploadResponse.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to upload report: {Status} {Content}",
                    uploadResponse.StatusCode, uploadContent);
                return $"Error: Failed to upload: {uploadResponse.StatusCode}";
            }

            // Extract the web URL from the response
            using var uploadDoc = JsonDocument.Parse(uploadContent);
            var webUrl = uploadDoc.RootElement.TryGetProperty("webUrl", out var wu)
                ? wu.GetString() ?? "" : "";

            _logger.LogInformation("Report uploaded successfully: {WebUrl}", webUrl);
            return webUrl;

        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error uploading report to SharePoint");
            return $"Error: {ex.Message}";
        }
    }
}
