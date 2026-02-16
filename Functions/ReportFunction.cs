using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using SecurityAgent.Config;
using SecurityAgent.Services;
using System.Net;
using System.Text.Json;

namespace SecurityAgent.Functions;

public class ReportFunction
{
    private readonly ReportGeneratorService _reportGenerator;
    private readonly SharePointService _sharePoint;
    private readonly EmailService _email;
    private readonly AgentConfiguration _config;
    private readonly ILogger<ReportFunction> _logger;

    public ReportFunction(
        ReportGeneratorService reportGenerator,
        SharePointService sharePoint,
        EmailService email,
        AgentConfiguration config,
        ILogger<ReportFunction> logger)
    {
        _reportGenerator = reportGenerator;
        _sharePoint = sharePoint;
        _email = email;
        _config = config;
        _logger = logger;
    }

    /// <summary>
    /// Timer-triggered function — runs every 2 weeks (every other Monday at 11:00 UTC / 7:00 AM AST).
    /// CRON: "0 0 11 */14 * 1" doesn't work for biweekly, so we use weekly on Monday
    /// and track execution to skip alternate weeks. 
    /// Alternative: use "0 0 11 1,15 * *" to run on 1st and 15th of each month.
    /// </summary>
    [Function("ScheduledReportGeneration")]
    public async Task RunScheduledReport(
        [TimerTrigger("0 0 11 1,15 * *")] TimerInfo timerInfo)
    {
        _logger.LogInformation("Scheduled report generation triggered at {Time}", DateTime.UtcNow);

        try
        {
            await GenerateAndDistributeReportsAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Scheduled report generation failed");
            throw;
        }
    }

    /// <summary>
    /// HTTP-triggered function for on-demand report generation.
    /// POST /api/generate-report
    /// Body: { "report": "devices" | "sharepoint" | "both", "email": true/false, "emailTo": "override@email.com" }
    /// </summary>
    [Function("GenerateReportOnDemand")]
    public async Task<HttpResponseData> RunOnDemand(
        [HttpTrigger(AuthorizationLevel.Function, "post", Route = "generate-report")] HttpRequestData req)
    {
        _logger.LogInformation("On-demand report generation requested");

        string reportType = "both";
        bool sendEmail = false;
        string? emailTo = null;

        try
        {
            var body = await req.ReadAsStringAsync();
            if (!string.IsNullOrEmpty(body))
            {
                using var doc = JsonDocument.Parse(body);
                reportType = doc.RootElement.TryGetProperty("report", out var rt) ? rt.GetString() ?? "both" : "both";
                sendEmail = doc.RootElement.TryGetProperty("email", out var em) && em.GetBoolean();
                emailTo = doc.RootElement.TryGetProperty("emailTo", out var et) ? et.GetString() : null;
            }
        }
        catch { /* Use defaults */ }

        try
        {
            var results = new Dictionary<string, object>();

            if (reportType is "devices" or "both")
            {
                var (url, success) = await GenerateSingleReportAsync("devices", sendEmail, emailTo);
                results["devicesReport"] = new { sharePointUrl = url, emailSent = success && sendEmail };
            }

            if (reportType is "sharepoint" or "both")
            {
                var (url, success) = await GenerateSingleReportAsync("sharepoint", sendEmail, emailTo);
                results["sharePointReport"] = new { sharePointUrl = url, emailSent = success && sendEmail };
            }

            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteAsJsonAsync(results);
            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "On-demand report generation failed");
            var errorResponse = req.CreateResponse(HttpStatusCode.InternalServerError);
            await errorResponse.WriteAsJsonAsync(new { error = ex.Message });
            return errorResponse;
        }
    }

    /// <summary>
    /// Generate both reports and distribute via SharePoint, email, and Teams.
    /// </summary>
    private async Task GenerateAndDistributeReportsAsync()
    {
        var now = DateTime.UtcNow;
        var dateStamp = now.ToString("yyyy-MM-dd");

        // Generate both reports
        _logger.LogInformation("Generating Devices & Vulnerabilities Report...");
        var devicesHtml = await _reportGenerator.GenerateDevicesReportAsync();
        var devicesFileName = $"Devices-Vulnerabilities-Report-{dateStamp}.html";

        _logger.LogInformation("Generating SharePoint & External Access Report...");
        var sharePointHtml = await _reportGenerator.GenerateSharePointReportAsync();
        var sharePointFileName = $"SharePoint-External-Access-Report-{dateStamp}.html";

        // Upload to SharePoint
        var devicesUrl = await _sharePoint.UploadReportAsync(devicesFileName, devicesHtml);
        var sharePointUrl = await _sharePoint.UploadReportAsync(sharePointFileName, sharePointHtml);

        _logger.LogInformation("Reports uploaded to SharePoint: Devices={DevicesUrl}, SharePoint={SharePointUrl}",
            devicesUrl, sharePointUrl);

        // Send notification emails with HTML reports attached
        if (!string.IsNullOrEmpty(_config.ReportRecipients))
        {
            await _email.SendReportWithAttachmentAsync(
                "Devices & Vulnerabilities Report", devicesUrl,
                devicesHtml, devicesFileName);

            await _email.SendReportWithAttachmentAsync(
                "SharePoint & External Access Report", sharePointUrl,
                sharePointHtml, sharePointFileName);
        }

        // Post to Teams webhook
        if (!string.IsNullOrEmpty(_config.ReportTeamsWebhookUrl))
        {
            await PostTeamsNotificationAsync(devicesUrl, sharePointUrl);
        }

        _logger.LogInformation("Scheduled report generation completed successfully");
    }

    /// <summary>
    /// Generate a single report and optionally email it.
    /// </summary>
    private async Task<(string url, bool emailSent)> GenerateSingleReportAsync(
        string reportType, bool sendEmail, string? emailTo)
    {
        var now = DateTime.UtcNow;
        var dateStamp = now.ToString("yyyy-MM-dd");
        string html, fileName, reportName;

        if (reportType == "devices")
        {
            html = await _reportGenerator.GenerateDevicesReportAsync();
            fileName = $"Devices-Vulnerabilities-Report-{dateStamp}.html";
            reportName = "Devices & Vulnerabilities Report";
        }
        else
        {
            html = await _reportGenerator.GenerateSharePointReportAsync();
            fileName = $"SharePoint-External-Access-Report-{dateStamp}.html";
            reportName = "SharePoint & External Access Report";
        }

        // Upload to SharePoint
        var url = await _sharePoint.UploadReportAsync(fileName, html);

        // Send notification email with report attached if requested
        bool emailSent = false;
        if (sendEmail)
        {
            emailSent = await _email.SendReportWithAttachmentAsync(
                reportName, url, html, fileName, emailTo);
        }

        return (url, emailSent);
    }

    /// <summary>
    /// Post a summary notification to Teams via incoming webhook.
    /// </summary>
    private async Task PostTeamsNotificationAsync(string devicesUrl, string sharePointUrl)
    {
        try
        {
            using var httpClient = new HttpClient();
            var card = new
            {
                type = "message",
                attachments = new[]
                {
                    new
                    {
                        contentType = "application/vnd.microsoft.card.adaptive",
                        contentUrl = (string?)null,
                        content = new
                        {
                            type = "AdaptiveCard",
                            version = "1.4",
                            msteams = new { width = "Full" },
                            body = new object[]
                            {
                                new {
                                    type = "TextBlock",
                                    text = "🛡️ Security Reports Generated",
                                    weight = "Bolder",
                                    size = "Large"
                                },
                                new {
                                    type = "TextBlock",
                                    text = $"Biweekly security reports have been generated and uploaded to SharePoint.",
                                    wrap = true
                                },
                                new {
                                    type = "ActionSet",
                                    actions = new object[]
                                    {
                                        new {
                                            type = "Action.OpenUrl",
                                            title = "📊 Devices & Vulnerabilities",
                                            url = devicesUrl
                                        },
                                        new {
                                            type = "Action.OpenUrl",
                                            title = "🔗 SharePoint & External Access",
                                            url = sharePointUrl
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            };

            var json = JsonSerializer.Serialize(card);
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");
            var response = await httpClient.PostAsync(_config.ReportTeamsWebhookUrl, content);

            if (response.IsSuccessStatusCode)
                _logger.LogInformation("Teams notification posted successfully");
            else
                _logger.LogWarning("Teams webhook returned {Status}", response.StatusCode);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to post Teams notification");
        }
    }
}
