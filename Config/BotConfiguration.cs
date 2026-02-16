namespace SecurityAgent.Config;

public class BotConfiguration
{
    /// <summary>
    /// The App ID (Client ID) from the Azure Bot registration.
    /// Same as the AgentConfiguration ClientId if reusing the same app registration.
    /// </summary>
    public string MicrosoftAppId { get; set; } = "";

    /// <summary>
    /// The App Password (Client Secret) for bot authentication.
    /// Same as AgentConfiguration ClientSecret if reusing the same app registration.
    /// </summary>
    public string MicrosoftAppPassword { get; set; } = "";

    /// <summary>
    /// The tenant ID for single-tenant bots.
    /// </summary>
    public string MicrosoftAppTenantId { get; set; } = "";
}
