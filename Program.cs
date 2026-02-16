using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Bot.Builder;
using Microsoft.Bot.Builder.Integration.AspNet.Core;
using Microsoft.Bot.Connector.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecurityAgent.Bot;
using SecurityAgent.Config;
using SecurityAgent.Services;

var host = new HostBuilder()
    .ConfigureFunctionsWebApplication()
    .ConfigureServices((context, services) =>
    {
        // Bind configuration
        var config = context.Configuration;
        var agentConfig = new AgentConfiguration();
        config.GetSection("AgentConfiguration").Bind(agentConfig);

        // If running in Azure, pull secrets from Key Vault
        var keyVaultUri = config["KeyVaultUri"];
        if (!string.IsNullOrEmpty(keyVaultUri))
        {
            var secretClient = new SecretClient(
                new Uri(keyVaultUri),
                new DefaultAzureCredential());

            agentConfig.ClientSecret = secretClient
                .GetSecret(config["KeyVault:ClientSecretName"] ?? "SecurityAgent-ClientSecret")
                .Value.Value;

            // If OpenAI key is also in Key Vault
            var openAiSecretName = config["KeyVault:OpenAiKeyName"];
            if (!string.IsNullOrEmpty(openAiSecretName))
            {
                agentConfig.OpenAiApiKey = secretClient
                    .GetSecret(openAiSecretName).Value.Value;
            }
        }
        else
        {
            // Local development — read from local.settings.json or user secrets
            agentConfig.ClientSecret = config["AgentConfiguration:ClientSecret"] ?? "";
            agentConfig.OpenAiApiKey = config["AgentConfiguration:OpenAiApiKey"] ?? "";
        }

        // Ensure required config is present
        agentConfig.TenantId = config["AgentConfiguration:TenantId"] ?? agentConfig.TenantId;
        agentConfig.ClientId = config["AgentConfiguration:ClientId"] ?? agentConfig.ClientId;
        agentConfig.OpenAiEndpoint = config["AgentConfiguration:OpenAiEndpoint"] ?? agentConfig.OpenAiEndpoint;
        agentConfig.DeploymentName = config["AgentConfiguration:DeploymentName"] ?? agentConfig.DeploymentName;

        // Report configuration
        agentConfig.ReportSharePointSiteId = config["AgentConfiguration:ReportSharePointSiteId"] ?? agentConfig.ReportSharePointSiteId;
        agentConfig.ReportDocumentLibrary = config["AgentConfiguration:ReportDocumentLibrary"] ?? agentConfig.ReportDocumentLibrary;
        agentConfig.ReportFolderPath = config["AgentConfiguration:ReportFolderPath"] ?? agentConfig.ReportFolderPath;
        agentConfig.ReportSharedMailbox = config["AgentConfiguration:ReportSharedMailbox"] ?? agentConfig.ReportSharedMailbox;
        agentConfig.ReportRecipients = config["AgentConfiguration:ReportRecipients"] ?? agentConfig.ReportRecipients;
        agentConfig.ReportTeamsWebhookUrl = config["AgentConfiguration:ReportTeamsWebhookUrl"] ?? agentConfig.ReportTeamsWebhookUrl;
        agentConfig.ReportLogoSvgBase64 = config["AgentConfiguration:ReportLogoSvgBase64"] ?? agentConfig.ReportLogoSvgBase64;
        agentConfig.OrganizationDomain = config["AgentConfiguration:OrganizationDomain"] ?? agentConfig.OrganizationDomain;

        services.AddSingleton(agentConfig);

        // Register services
        services.AddSingleton<TokenService>();
        services.AddHttpClient();
        services.AddSingleton<GraphApiService>();
        services.AddSingleton<DefenderApiService>();
        services.AddSingleton<IntuneService>();
        services.AddSingleton<AdvancedHuntingService>();
        services.AddSingleton<ToolDefinitionService>();
        services.AddSingleton<ToolExecutionService>();
        services.AddSingleton<AgentOrchestrator>();

        // Report generation services
        services.AddSingleton<ReportGeneratorService>();
        services.AddSingleton<SharePointService>();
        services.AddSingleton<EmailService>();

        // Conversation state persistence — uses the Function App's storage account
        var storageConnectionString = config["AzureWebJobsStorage"] ?? "UseDevelopmentStorage=true";
        services.AddSingleton(sp =>
            new ConversationStateService(
                storageConnectionString,
                sp.GetRequiredService<ILogger<ConversationStateService>>()));

        // ── Bot Framework registration ──

        // Bot authentication — reuses the same app registration as the agent.
        // We set the required Bot Framework config keys so the SDK picks them up.
        var botConfig = new Dictionary<string, string?>
        {
            ["MicrosoftAppType"] = "SingleTenant",
            ["MicrosoftAppId"] = config["BotConfiguration__MicrosoftAppId"]
                ?? config["BotConfiguration:MicrosoftAppId"]
                ?? agentConfig.ClientId,
            ["MicrosoftAppPassword"] = config["BotConfiguration__MicrosoftAppPassword"]
                ?? config["BotConfiguration:MicrosoftAppPassword"]
                ?? agentConfig.ClientSecret,
            ["MicrosoftAppTenantId"] = config["BotConfiguration__MicrosoftAppTenantId"]
                ?? config["BotConfiguration:MicrosoftAppTenantId"]
                ?? agentConfig.TenantId
        };

        var botConfiguration = new ConfigurationBuilder()
            .AddInMemoryCollection(botConfig)
            .Build();

        services.AddSingleton<IConfiguration>(sp =>
        {
            // Merge bot config with existing config for Bot Framework SDK
            return new ConfigurationBuilder()
                .AddConfiguration(config)
                .AddInMemoryCollection(botConfig)
                .Build();
        });

        services.AddSingleton<BotFrameworkAuthentication, ConfigurationBotFrameworkAuthentication>();
        services.AddSingleton<IBotFrameworkHttpAdapter, AdapterWithErrorHandler>();
        services.AddSingleton<IBot, SecurityAgentBot>();
    })
    .Build();

host.Run();
