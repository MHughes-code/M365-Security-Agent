using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using SecurityAgent.Models;
using SecurityAgent.Services;
using System.Text.Json;
using OpenAI.Chat;

namespace SecurityAgent.Functions;

public class SecurityAgentFunction
{
    private readonly AgentOrchestrator _agent;
    private readonly ConversationStateService _stateService;
    private readonly ILogger<SecurityAgentFunction> _logger;

    public SecurityAgentFunction(
        AgentOrchestrator agent,
        ConversationStateService stateService,
        ILogger<SecurityAgentFunction> logger)
    {
        _agent = agent;
        _stateService = stateService;
        _logger = logger;
    }

    /// <summary>
    /// Main endpoint for the security agent.
    /// POST /api/security-agent
    /// Body: { "question": "...", "conversationId": "..." }
    /// </summary>
    [Function("SecurityAgent")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post", Route = "security-agent")] HttpRequest req)
    {
        _logger.LogInformation("Security agent invoked.");

        // Parse request body
        string requestBody;
        using (var reader = new StreamReader(req.Body))
        {
            requestBody = await reader.ReadToEndAsync();
        }

        AgentRequest? agentRequest;
        try
        {
            agentRequest = JsonSerializer.Deserialize<AgentRequest>(requestBody,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Failed to parse request body.");
            return new BadRequestObjectResult(new { error = "Invalid request body. Expected: { \"question\": \"...\", \"conversationId\": \"...\" }" });
        }

        if (agentRequest == null || string.IsNullOrWhiteSpace(agentRequest.Question))
        {
            return new BadRequestObjectResult(new { error = "Missing 'question' field." });
        }

        // Generate or reuse conversation ID
        var conversationId = agentRequest.ConversationId ?? Guid.NewGuid().ToString();

        // Check if we're resuming an approval flow
        IList<ChatMessage>? history = null;
        if (!string.IsNullOrEmpty(agentRequest.ConversationId))
        {
            history = await _stateService.RetrieveAndDeleteStateAsync(agentRequest.ConversationId);
            if (history != null)
            {
                _logger.LogInformation("Resuming conversation {ConversationId} after approval.",
                    agentRequest.ConversationId);
            }
        }

        // Run the agent
        AgentResponse result;
        try
        {
            result = await _agent.RunAgentAsync(agentRequest.Question, history);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Agent execution failed.");
            return new ObjectResult(new { error = "Agent execution failed.", details = ex.Message })
            {
                StatusCode = 500
            };
        }

        // If awaiting approval, save the conversation state
        if (result.AwaitingApproval && result.ConversationHistory != null)
        {
            await _stateService.SaveStateAsync(conversationId, result.ConversationHistory);
            _logger.LogInformation("Conversation {ConversationId} saved — awaiting approval.",
                conversationId);
        }

        return new OkObjectResult(new
        {
            message = result.Message,
            conversationId,
            awaitingApproval = result.AwaitingApproval
        });
    }
}

/// <summary>
/// Request model for the security agent endpoint.
/// </summary>
public class AgentRequest
{
    /// <summary>
    /// The natural language question to ask the agent.
    /// </summary>
    public string Question { get; set; } = "";

    /// <summary>
    /// Optional conversation ID for resuming an approval flow.
    /// If provided and a pending conversation exists, the agent
    /// will resume from where it left off.
    /// </summary>
    public string? ConversationId { get; set; }
}
