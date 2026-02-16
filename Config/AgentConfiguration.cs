namespace SecurityAgent.Config;

public class AgentConfiguration
{
    // Entra ID App Registration
    public string TenantId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";

    // Azure OpenAI
    public string OpenAiEndpoint { get; set; } = "";
    public string OpenAiApiKey { get; set; } = "";
    public string DeploymentName { get; set; } = "gpt-41-mini-security-agent";

    // API Endpoints
    public string GraphBaseUrl { get; set; } = "https://graph.microsoft.com/v1.0";
    public string DefenderBaseUrl { get; set; } = "https://api.securitycenter.microsoft.com/api";

    // Token scopes
    public string GraphScope { get; set; } = "https://graph.microsoft.com/.default";
    public string DefenderScope { get; set; } = "https://api.securitycenter.microsoft.com/.default";

    // Agent behavior
    public int MaxAgentIterations { get; set; } = 15;
    public float Temperature { get; set; } = 0.1f;
    public int MaxHuntingResults { get; set; } = 500;

    // Report settings
    public string ReportSharePointSiteId { get; set; } = "";
    public string ReportDocumentLibrary { get; set; } = "Documents"; // drive/library name
    public string ReportFolderPath { get; set; } = "Folder/Subfolder"; // subfolder path within the library
    public string ReportSharedMailbox { get; set; } = "email@yourdomain.com";
    public string ReportRecipients { get; set; } = ""; // comma-separated emails
    public string ReportTeamsWebhookUrl { get; set; } = "";
    public string ReportLogoSvgBase64 { get; set; } = ""; // white SVG logo, base64 encoded
    public string OrganizationDomain { get; set; } = "yourdomain.com";
}
