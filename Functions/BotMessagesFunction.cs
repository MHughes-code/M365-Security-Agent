using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Bot.Builder;
using Microsoft.Bot.Builder.Integration.AspNet.Core;
using Microsoft.Extensions.Logging;

namespace SecurityAgent.Functions;

/// <summary>
/// HTTP trigger that handles incoming Bot Framework messages from Teams.
/// This is the endpoint configured in the Azure Bot resource's messaging endpoint.
/// Route: POST /api/messages
/// </summary>
public class BotMessagesFunction
{
    private readonly IBotFrameworkHttpAdapter _adapter;
    private readonly IBot _bot;
    private readonly ILogger<BotMessagesFunction> _logger;

    public BotMessagesFunction(
        IBotFrameworkHttpAdapter adapter,
        IBot bot,
        ILogger<BotMessagesFunction> logger)
    {
        _adapter = adapter;
        _bot = bot;
        _logger = logger;
    }

    [Function("BotMessages")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "messages")] HttpRequest req)
    {
        _logger.LogInformation("Bot message received.");

        try
        {
            // The adapter handles Bot Framework authentication and deserialization,
            // then routes to the bot's OnMessageActivityAsync
            await _adapter.ProcessAsync(req, req.HttpContext.Response, _bot);
            return new EmptyResult();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing bot message.");
            return new ObjectResult(new { error = "Bot message processing failed." })
            {
                StatusCode = 500
            };
        }
    }
}
