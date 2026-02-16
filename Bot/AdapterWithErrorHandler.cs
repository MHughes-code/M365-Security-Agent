using Microsoft.Bot.Builder;
using Microsoft.Bot.Builder.Integration.AspNet.Core;
using Microsoft.Bot.Connector.Authentication;
using Microsoft.Extensions.Logging;

namespace SecurityAgent.Bot;

/// <summary>
/// Bot adapter with error handling.
/// Handles authentication and routing of Bot Framework protocol messages.
/// </summary>
public class AdapterWithErrorHandler : CloudAdapter
{
    public AdapterWithErrorHandler(
        BotFrameworkAuthentication auth,
        ILogger<AdapterWithErrorHandler> logger)
        : base(auth, logger)
    {
        OnTurnError = async (turnContext, exception) =>
        {
            logger.LogError(exception, "Bot turn error: {Message}", exception.Message);

            // Send a message to the user
            await turnContext.SendActivityAsync(
                MessageFactory.Text("⚠️ An error occurred while processing your request. Please try again."));
        };
    }
}
