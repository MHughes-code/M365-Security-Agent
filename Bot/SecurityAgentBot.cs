using Microsoft.Bot.Builder;
using Microsoft.Bot.Schema;
using Microsoft.Extensions.Logging;
using OpenAI.Chat;
using SecurityAgent.Models;
using SecurityAgent.Services;

namespace SecurityAgent.Bot;

/// <summary>
/// Handles Teams bot messages by routing them to the existing AgentOrchestrator.
/// Uses ConversationStateService for persistent Tier 3 approval state.
/// </summary>
public class SecurityAgentBot : ActivityHandler
{
    private readonly AgentOrchestrator _agent;
    private readonly ConversationStateService _stateService;
    private readonly ILogger<SecurityAgentBot> _logger;

    public SecurityAgentBot(
        AgentOrchestrator agent,
        ConversationStateService stateService,
        ILogger<SecurityAgentBot> logger)
    {
        _agent = agent;
        _stateService = stateService;
        _logger = logger;
    }

    protected override async Task OnMessageActivityAsync(
        ITurnContext<IMessageActivity> turnContext,
        CancellationToken cancellationToken)
    {
        var userMessage = turnContext.Activity.Text?.Trim();
        var conversationId = turnContext.Activity.Conversation.Id;
        var userName = turnContext.Activity.From?.Name ?? "Unknown";

        if (string.IsNullOrEmpty(userMessage))
        {
            await turnContext.SendActivityAsync(
                MessageFactory.Text("Please send a text message with your security question."),
                cancellationToken);
            return;
        }

        _logger.LogInformation("Teams message from {User} in {ConversationId}: {Message}",
            userName, conversationId, userMessage.Length > 200 ? userMessage[..200] + "..." : userMessage);

        // Show typing indicator while processing
        await turnContext.SendActivityAsync(
            new Activity { Type = ActivityTypes.Typing },
            cancellationToken);

        // Check if this is an approval response for a pending Tier 3 query
        IList<ChatMessage>? history = null;
        var isApproval = IsApprovalResponse(userMessage);

        if (isApproval)
        {
            history = await _stateService.RetrieveAndDeleteStateAsync(conversationId);
            if (history != null)
            {
                _logger.LogInformation("Resuming conversation {ConversationId} after approval.", conversationId);
            }
        }
        else if (await _stateService.HasPendingStateAsync(conversationId))
        {
            // User sent a new question instead of approving — clear the pending state
            await _stateService.DeleteStateAsync(conversationId);
            _logger.LogInformation("Pending approval cleared for {ConversationId} — new question received.", conversationId);
        }

        try
        {
            var result = await _agent.RunAgentAsync(userMessage, history);

            // If the agent is waiting for Tier 3 approval, save state
            if (result.AwaitingApproval && result.ConversationHistory != null)
            {
                await _stateService.SaveStateAsync(conversationId, result.ConversationHistory);
                _logger.LogInformation("Conversation {ConversationId} paused — awaiting KQL approval.", conversationId);
            }

            // Send the response — split if it's too long for Teams (max ~28KB)
            await SendResponseAsync(turnContext, result.Message, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Agent execution failed for Teams message.");
            await turnContext.SendActivityAsync(
                MessageFactory.Text("⚠️ Sorry, something went wrong while processing your request. Please try again or rephrase your question."),
                cancellationToken);
        }
    }

    protected override async Task OnMembersAddedAsync(
        IList<ChannelAccount> membersAdded,
        ITurnContext<IConversationUpdateActivity> turnContext,
        CancellationToken cancellationToken)
    {
        foreach (var member in membersAdded)
        {
            if (member.Id != turnContext.Activity.Recipient.Id)
            {
                await turnContext.SendActivityAsync(
                    MessageFactory.Text(
                        "👋 Hi! I'm the Security Agent. I can help you investigate security incidents, " +
                        "check device compliance, hunt for threats, and more.\n\n" +
                        "Try asking me things like:\n" +
                        "- \"Are there any active security incidents?\"\n" +
                        "- \"How many devices are compliant?\"\n" +
                        "- \"Show me noncompliant devices\"\n" +
                        "- \"Were there any risky sign-ins this week?\"\n" +
                        "- \"What vulnerabilities exist across our devices?\""),
                    cancellationToken);
            }
        }
    }

    /// <summary>
    /// Determines if the user's message is an approval for a pending Tier 3 query.
    /// </summary>
    private static bool IsApprovalResponse(string message)
    {
        var lower = message.ToLowerInvariant().Trim();
        return lower is "yes" or "y" or "run it" or "go ahead" or "approve" or "execute"
            or "do it" or "confirmed" or "ok" or "sure" or "proceed";
    }

    /// <summary>
    /// Send a response to Teams. Tries an Adaptive Card for responses with
    /// markdown tables; falls back to emoji-enhanced text otherwise.
    /// </summary>
    private static async Task SendResponseAsync(
        ITurnContext turnContext,
        string message,
        CancellationToken cancellationToken)
    {
        // Try Adaptive Card for responses with markdown tables
        var card = AdaptiveCardBuilder.TryBuildCard(message);
        if (card != null)
        {
            await turnContext.SendActivityAsync(
                MessageFactory.Attachment(card),
                cancellationToken);
            return;
        }

        // Fall back to emoji-enhanced text
        var enhanced = MessageFormatter.EnhanceMessage(message);
        const int maxLength = 4000;

        if (enhanced.Length <= maxLength)
        {
            await turnContext.SendActivityAsync(
                MessageFactory.Text(enhanced),
                cancellationToken);
            return;
        }

        var chunks = SplitMessage(enhanced, maxLength);
        foreach (var chunk in chunks)
        {
            await turnContext.SendActivityAsync(
                MessageFactory.Text(chunk),
                cancellationToken);
        }
    }

    /// <summary>
    /// Split a long message into chunks, preferring paragraph boundaries.
    /// </summary>
    private static List<string> SplitMessage(string message, int maxLength)
    {
        var chunks = new List<string>();
        var remaining = message;

        while (remaining.Length > maxLength)
        {
            // Try to split at a paragraph boundary
            var splitIndex = remaining.LastIndexOf("\n\n", maxLength, StringComparison.Ordinal);
            if (splitIndex < maxLength / 2)
            {
                // No good paragraph break — try a single newline
                splitIndex = remaining.LastIndexOf('\n', maxLength);
            }
            if (splitIndex < maxLength / 2)
            {
                // No good newline — just split at max length
                splitIndex = maxLength;
            }

            chunks.Add(remaining[..splitIndex].TrimEnd());
            remaining = remaining[splitIndex..].TrimStart();
        }

        if (remaining.Length > 0)
            chunks.Add(remaining);

        return chunks;
    }
}
