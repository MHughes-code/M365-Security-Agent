using Azure.Data.Tables;
using Microsoft.Extensions.Logging;
using OpenAI.Chat;
using System.Text.Json;

namespace SecurityAgent.Services;

/// <summary>
/// Persists conversation state (chat history) to Azure Table Storage.
/// Used by both the HTTP endpoint and the Teams bot to survive function recycles
/// during the Tier 3 KQL approval flow.
/// </summary>
public class ConversationStateService
{
    private readonly TableClient _tableClient;
    private readonly ILogger<ConversationStateService> _logger;
    private const string TableName = "ConversationState";
    private const string PartitionKey = "approval"; // All approval states share a partition

    public ConversationStateService(
        string connectionString,
        ILogger<ConversationStateService> logger)
    {
        _logger = logger;
        _tableClient = new TableClient(connectionString, TableName);
        _tableClient.CreateIfNotExists();
    }

    /// <summary>
    /// Save conversation history for a pending Tier 3 approval.
    /// </summary>
    public async Task SaveStateAsync(string conversationId, IList<ChatMessage> history)
    {
        try
        {
            var serialized = SerializeHistory(history);
            var entity = new TableEntity(PartitionKey, SanitizeKey(conversationId))
            {
                { "History", serialized },
                { "CreatedAt", DateTimeOffset.UtcNow }
            };

            await _tableClient.UpsertEntityAsync(entity);
            _logger.LogInformation("Conversation state saved for {ConversationId} ({Size} bytes).",
                conversationId, serialized.Length);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save conversation state for {ConversationId}.", conversationId);
            throw;
        }
    }

    /// <summary>
    /// Retrieve and delete conversation history for an approved Tier 3 query.
    /// Returns null if no pending state exists.
    /// </summary>
    public async Task<IList<ChatMessage>?> RetrieveAndDeleteStateAsync(string conversationId)
    {
        try
        {
            var sanitizedKey = SanitizeKey(conversationId);
            var response = await _tableClient.GetEntityIfExistsAsync<TableEntity>(PartitionKey, sanitizedKey);

            if (!response.HasValue || response.Value == null)
            {
                _logger.LogDebug("No pending state for {ConversationId}.", conversationId);
                return null;
            }

            var entity = response.Value;
            var historyJson = entity.GetString("History");

            // Delete immediately — it's a one-time use
            await _tableClient.DeleteEntityAsync(PartitionKey, sanitizedKey);

            var history = DeserializeHistory(historyJson);
            _logger.LogInformation("Conversation state retrieved and deleted for {ConversationId}.", conversationId);
            return history;
        }
        catch (Azure.RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve conversation state for {ConversationId}.", conversationId);
            return null;
        }
    }

    /// <summary>
    /// Check if a conversation has pending approval state.
    /// </summary>
    public async Task<bool> HasPendingStateAsync(string conversationId)
    {
        try
        {
            var response = await _tableClient.GetEntityIfExistsAsync<TableEntity>(
                PartitionKey, SanitizeKey(conversationId));
            return response.HasValue;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Delete pending state without retrieving it (e.g., user asked a new question).
    /// </summary>
    public async Task DeleteStateAsync(string conversationId)
    {
        try
        {
            await _tableClient.DeleteEntityAsync(PartitionKey, SanitizeKey(conversationId));
            _logger.LogInformation("Pending state cleared for {ConversationId}.", conversationId);
        }
        catch (Azure.RequestFailedException ex) when (ex.Status == 404)
        {
            // Already gone — that's fine
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete conversation state for {ConversationId}.", conversationId);
        }
    }

    /// <summary>
    /// Clean up expired conversation states (older than 1 hour).
    /// Call this periodically or on a timer trigger.
    /// </summary>
    public async Task CleanupExpiredStatesAsync()
    {
        try
        {
            var cutoff = DateTimeOffset.UtcNow.AddHours(-1);
            var expiredEntities = _tableClient.QueryAsync<TableEntity>(
                filter: $"PartitionKey eq '{PartitionKey}' and CreatedAt lt datetime'{cutoff:yyyy-MM-ddTHH:mm:ssZ}'");

            var count = 0;
            await foreach (var entity in expiredEntities)
            {
                await _tableClient.DeleteEntityAsync(entity.PartitionKey, entity.RowKey);
                count++;
            }

            if (count > 0)
                _logger.LogInformation("Cleaned up {Count} expired conversation states.", count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during conversation state cleanup.");
        }
    }

    // ── Serialization ──
    // ChatMessage subtypes can't be directly JSON-serialized in a round-trip friendly way,
    // so we use a portable intermediate format.

    private static string SerializeHistory(IList<ChatMessage> history)
    {
        var portable = new List<PortableMessage>();

        foreach (var msg in history)
        {
            var pm = new PortableMessage();

            switch (msg)
            {
                case SystemChatMessage sys:
                    pm.Role = "system";
                    pm.Content = sys.Content.FirstOrDefault()?.Text ?? "";
                    break;

                case UserChatMessage user:
                    pm.Role = "user";
                    pm.Content = user.Content.FirstOrDefault()?.Text ?? "";
                    break;

                case AssistantChatMessage asst:
                    pm.Role = "assistant";
                    // Assistant messages may have text content and/or tool calls
                    pm.Content = asst.Content.FirstOrDefault()?.Text ?? "";
                    if (asst.ToolCalls?.Count > 0)
                    {
                        pm.ToolCalls = asst.ToolCalls.Select(tc => new PortableToolCall
                        {
                            Id = tc.Id,
                            FunctionName = tc.FunctionName,
                            FunctionArguments = tc.FunctionArguments.ToString()
                        }).ToList();
                    }
                    break;

                case ToolChatMessage tool:
                    pm.Role = "tool";
                    pm.ToolCallId = tool.ToolCallId;
                    pm.Content = tool.Content.FirstOrDefault()?.Text ?? "";
                    break;

                default:
                    continue; // Skip unknown types
            }

            portable.Add(pm);
        }

        return JsonSerializer.Serialize(portable);
    }

    private static IList<ChatMessage> DeserializeHistory(string json)
    {
        var portable = JsonSerializer.Deserialize<List<PortableMessage>>(json)
            ?? throw new InvalidOperationException("Failed to deserialize conversation history.");

        var messages = new List<ChatMessage>();

        foreach (var pm in portable)
        {
            switch (pm.Role)
            {
                case "system":
                    messages.Add(new SystemChatMessage(pm.Content ?? ""));
                    break;

                case "user":
                    messages.Add(new UserChatMessage(pm.Content ?? ""));
                    break;

                case "assistant":
                    if (pm.ToolCalls?.Count > 0)
                    {
                        // Reconstruct assistant message with tool calls
                        var toolCalls = pm.ToolCalls.Select(tc =>
                            ChatToolCall.CreateFunctionToolCall(
                                tc.Id ?? "",
                                tc.FunctionName ?? "",
                                BinaryData.FromString(tc.FunctionArguments ?? "{}")
                            )).ToList();

                        var asstMsg = new AssistantChatMessage(pm.Content ?? "");
                        foreach (var tc in toolCalls)
                        {
                            asstMsg.ToolCalls.Add(tc);
                        }
                        messages.Add(asstMsg);
                    }
                    else
                    {
                        messages.Add(new AssistantChatMessage(pm.Content ?? ""));
                    }
                    break;

                case "tool":
                    messages.Add(new ToolChatMessage(pm.ToolCallId ?? "", pm.Content ?? ""));
                    break;
            }
        }

        return messages;
    }

    /// <summary>
    /// Table Storage row keys can't contain / \ # ? or control characters.
    /// Teams conversation IDs often contain these, so we sanitize.
    /// </summary>
    private static string SanitizeKey(string key)
    {
        // Replace disallowed characters with underscores
        return key.Replace("/", "_")
                   .Replace("\\", "_")
                   .Replace("#", "_")
                   .Replace("?", "_")
                   .Replace("\t", "_")
                   .Replace("\n", "_")
                   .Replace("\r", "_");
    }

    // ── Portable message format for JSON serialization ──

    private class PortableMessage
    {
        public string Role { get; set; } = "";
        public string? Content { get; set; }
        public string? ToolCallId { get; set; }
        public List<PortableToolCall>? ToolCalls { get; set; }
    }

    private class PortableToolCall
    {
        public string? Id { get; set; }
        public string? FunctionName { get; set; }
        public string? FunctionArguments { get; set; }
    }
}
