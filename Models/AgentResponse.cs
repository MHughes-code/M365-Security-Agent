using OpenAI.Chat;

namespace SecurityAgent.Models;

/// <summary>
/// Represents the result of an agent run — either a final answer
/// or a paused state awaiting user approval for a dynamic KQL query.
/// </summary>
public class AgentResponse
{
    /// <summary>
    /// The agent's message to display to the user.
    /// </summary>
    public string Message { get; set; } = "";

    /// <summary>
    /// True if the agent is paused, waiting for user approval of a dynamic KQL query.
    /// The caller should present the message (which includes the proposed query)
    /// and wait for the user to approve or reject before calling RunAgentAsync again.
    /// </summary>
    public bool AwaitingApproval { get; set; }

    /// <summary>
    /// The full conversation history (messages) so far.
    /// Must be passed back to RunAgentAsync when resuming after approval.
    /// </summary>
    public IList<ChatMessage>? ConversationHistory { get; set; }
}
