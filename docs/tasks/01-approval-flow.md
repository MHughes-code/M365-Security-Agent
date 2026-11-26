# 01 — Advanced Hunting approval flow

Branch: `task/01-approval-flow`
Depends on: task 00 merged.

## Goal

Make the "propose a KQL query, user approves, query runs" flow reliable. After this task:

- The KQL that runs is the exact text stored when it was proposed. The model never
  retypes it.
- Pending approvals survive cold starts and scale-out, and are per conversation.
- The user approves or rejects with buttons on an Adaptive Card, or by typing.
- Pausing for approval never calls the model a second time.

## Why (current defects this replaces)

1. `ToolExecutionService._pendingQuery` is an in-memory field on a singleton. It is lost
   on a new instance and shared between users.
2. `execute_approved_hunting_query` requires the model to retype the KQL and compares it
   as a string, so whitespace differences are rejected.
3. `SecurityAgentBot.IsApprovalResponse` only accepts exact words; "yes please" discards
   the pending query.
4. `AgentOrchestrator` makes a second model call (with tools enabled) to write the
   approval message and reads `Content[0]`, which throws when the model returns a tool
   call. If the proposal was one of several tool calls, the saved history has tool calls
   with no result.
5. `ConversationStateService` stores the whole history, including the system prompt, in
   one Table Storage property, which is limited to 64 KB.

## Design

`propose_advanced_hunting_query` becomes a tool whose **result is deferred**. When the
model calls it, the orchestrator stops, stores the proposal and the conversation so far,
and returns. When the user approves, code runs the stored KQL and supplies the query
output as that tool call's result, then the model loop continues. When the user rejects,
the tool result says so and the loop continues so the model can respond.

`execute_approved_hunting_query` is removed.

## Changes

### 1. `Models/PendingApproval.cs` (new)

```csharp
public class PendingApproval
{
    public string ProposalId { get; set; } = "";        // Guid "N" format
    public string ConversationId { get; set; } = "";
    public string? RequesterId { get; set; }            // Teams AadObjectId; null for HTTP
    public string? RequesterName { get; set; }
    public string ToolCallId { get; set; } = "";        // the deferred tool call
    public string Kql { get; set; } = "";
    public string Explanation { get; set; } = "";
    public string EstimatedScope { get; set; } = "";
    public DateTimeOffset CreatedAtUtc { get; set; }
    public IList<ChatMessage> History { get; set; } = new List<ChatMessage>();
}
```

`History` holds every message **except** the system message, up to and including the
assistant message that contains the proposal tool call, plus the tool results for any
other tool calls in that same assistant message.

### 2. `Models/AgentResponse.cs`

- Remove `ConversationHistory`.
- Add `public PendingApproval? Pending { get; set; }`.
- `AwaitingApproval` stays and is true exactly when `Pending` is not null.

### 3. `Services/ChatHistorySerializer.cs` (new, static)

Move `SerializeHistory`, `DeserializeHistory` and the two portable message classes out of
`ConversationStateService` into this class, as `public static string Serialize(IList<ChatMessage>)`
and `public static IList<ChatMessage> Deserialize(string)`.

Two fixes while moving:

- An assistant message with tool calls and no text must be rebuilt with the
  `AssistantChatMessage` constructor that takes the tool calls, not from an empty
  content string. (Check the constructor against the installed `OpenAI` package.)
- Concatenate all text content parts of a message instead of taking only the first.

### 4. `Services/PendingApprovalStore.cs` (new) — replaces `ConversationStateService`

Add NuGet package `Azure.Storage.Blobs` (current stable). This is the only package change.

```csharp
public interface IPendingApprovalStore
{
    Task SaveAsync(PendingApproval pending, CancellationToken ct = default);
    Task<PendingApproval?> PeekAsync(string conversationId, CancellationToken ct = default);
    Task<PendingApproval?> TakeAsync(string conversationId, CancellationToken ct = default);
    Task DeleteAsync(string conversationId, CancellationToken ct = default);
}
```

`BlobPendingApprovalStore`:

- Container `agent-state`, created if missing on first use (not in the constructor).
- Blob name `pending/{hex SHA-256 of conversationId}.json`. One pending approval per
  conversation; `SaveAsync` overwrites.
- Blob content: JSON of all `PendingApproval` fields, with `History` written through
  `ChatHistorySerializer`.
- `TakeAsync` downloads the blob, then deletes it with an `If-Match` condition on the
  ETag it read. If the blob is missing, or the delete fails with 404 or 412, return
  `null`. This guarantees a double-click runs the query once.
- `PeekAsync`, `TakeAsync`: if `CreatedAtUtc` is more than 60 minutes old, delete the
  blob and return `null`.
- Storage failures in `SaveAsync` throw. Failures in the other methods are logged and
  return `null` / do nothing.

Registration in `Program.cs`: build it from the existing `AzureWebJobsStorage`
connection string, exactly as `ConversationStateService` is built today, and register it
as `IPendingApprovalStore`. Delete `ConversationStateService.cs` and its registration.
Leave the `Azure.Data.Tables` package reference in place.

### 5. `Services/ApprovalIntent.cs` (new, static, pure)

```csharp
public enum ApprovalDecision { None, Approve, Reject }
public static ApprovalDecision Parse(string? message);
```

Normalise: trim, lower-case, remove `. , ! ?`, collapse whitespace. If the normalised
text is longer than 40 characters, return `None`. Otherwise:

- `Approve` if it equals, or starts with followed by a space, one of:
  `yes`, `y`, `yep`, `yeah`, `ok`, `okay`, `sure`, `approve`, `approved`, `run it`,
  `go ahead`, `do it`, `proceed`, `execute`, `confirmed`, `confirm`.
- `Reject` if it equals, or starts with followed by a space, one of:
  `no`, `n`, `nope`, `cancel`, `reject`, `stop`, `don't`, `dont`, `do not`.
- Otherwise `None`.

Check `Reject` first, so "no, don't run it" is a rejection.

### 6. `Services/ToolDefinitionService.cs`

- Delete the `execute_approved_hunting_query` tool.
- Replace the description of `propose_advanced_hunting_query` with:
  "Propose a custom KQL query for Advanced Hunting. The system shows the query to the
  user for approval. If approved, the system runs it and returns the rows as this tool's
  result. If rejected, the result says so. Use only when no other tool can answer. Do
  not write the KQL in your message text."
- Parameters unchanged.

### 7. `Services/ToolExecutionService.cs`

- Delete `_pendingQuery`, `IsAwaitingApproval`, `HandleProposal`,
  `HandleApprovedExecution`, and both Tier 3 cases in the `switch`.
- Add a `switch` case so that if `propose_advanced_hunting_query` ever reaches
  `ExecuteAsync`, it returns `{"error":"Proposals are handled by the orchestrator."}`.
- Add:

```csharp
public async Task<string> RunApprovedHuntingQueryAsync(string kql)
```

  It calls `_huntingService.RunDynamicQueryAsync(kql)` inside the same try/catch pattern
  `ExecuteAsync` uses, returning the JSON error object on exception.

### 8. `Services/AgentOrchestrator.cs`

System prompt: in the "Tier 3" capability list remove the `execute_approved_hunting_query`
line. Replace the whole "TIER 3 APPROVAL FLOW — STRICT RULES" block, including the
"CRITICAL" paragraph after it, with:

```
TIER 3 APPROVAL FLOW:
- When no Tier 1 or Tier 2 tool can answer, call propose_advanced_hunting_query with the
  kql_query, explanation and estimated_scope. Never write KQL in your message text.
- The system asks the user to approve. You do not ask for approval yourself.
- The tool result is either the query rows, an error from the query service, or a
  rejection. On rows: answer the question from them. On an error: fix the query and
  propose again, at most twice. On rejection: acknowledge and ask how to proceed.
```

Change nothing else in the prompt.

Public API:

```csharp
public record AgentCaller(string ConversationId, string? UserId, string? UserName);

public Task<AgentResponse> RunAgentAsync(string userMessage, AgentCaller caller);
public Task<AgentResponse> ResumeAfterApprovalAsync(PendingApproval pending, bool approved);
```

The `conversationHistory` parameter is removed. Both methods build the working message
list and call one shared private loop.

- `RunAgentAsync`: messages = system prompt + the user message (keep the existing
  `[Today: yyyy-MM-dd]` prefix).
- `ResumeAfterApprovalAsync`: messages = system prompt + `pending.History` + one
  `ToolChatMessage(pending.ToolCallId, result)` where `result` is
  - approved: the return value of `ToolExecutionService.RunApprovedHuntingQueryAsync(pending.Kql)`;
  - rejected: `{"status":"rejected","message":"The user rejected this query. It was not run."}`.
  The `AgentCaller` for the continued loop is rebuilt from `pending`.

Loop behaviour when the model returns tool calls:

1. Add the assistant message to the list.
2. For each tool call that is **not** `propose_advanced_hunting_query`: execute it and add
   its `ToolChatMessage`, as today.
3. For the **first** `propose_advanced_hunting_query` call in the message: do not add a
   tool message. Remember it as the deferred call.
4. For any further `propose_advanced_hunting_query` calls in the same message: add a tool
   message `{"error":"Only one query can await approval at a time. Propose it again after this one is resolved."}`.
5. If there is a deferred call, stop the loop and return an `AgentResponse` with
   `AwaitingApproval = true`, `Pending` filled in (new `ProposalId`, `CreatedAtUtc` = now,
   `History` = the message list without the system message), and `Message` set to the
   plain-text fallback described in section 9. Do **not** call the model again.
6. If the proposal arguments are missing `kql_query` or it is blank, do not defer: add a
   tool message `{"error":"kql_query is required."}` and continue the loop.

When the model returns a final answer, read the text by concatenating all text parts; if
there are none, use "I could not produce an answer. Please try rephrasing." Do not index
`Content[0]`.

The orchestrator does not touch the store. Callers save `Pending`.

### 9. `Bot/ApprovalCardBuilder.cs` (new, static)

```csharp
public static Attachment BuildRequestCard(PendingApproval pending);
public static Attachment BuildResolvedCard(PendingApproval pending, bool approved, string resolvedBy);
public static string BuildFallbackText(PendingApproval pending);
```

Build cards the same way `AdaptiveCardBuilder` does (dictionary, serialise, `JObject.Parse`),
schema version 1.5, `msteams.width = Full`.

Request card body, in order:

- TextBlock, bolder: "Approval needed: Advanced Hunting query"
- TextBlock, wrap: the explanation
- FactSet: "Scope" = estimated scope; "Requested by" = requester name or "Unknown"
- TextBlock, wrap, `fontType: Monospace`: the KQL, unmodified
- Actions: two `Action.Submit`
  - "Run query", `style: positive`, `data: {"action":"kql_approval","decision":"approve","proposalId":"<id>"}`
  - "Cancel", `style: destructive`, `data: {"action":"kql_approval","decision":"reject","proposalId":"<id>"}`

Resolved card: same body, no actions, plus a final TextBlock: "Approved by {name}" or
"Cancelled by {name}".

Fallback text (used as `AgentResponse.Message` and for the HTTP endpoint):

````
I'd like to run this Advanced Hunting query.

{explanation}

Scope: {estimatedScope}

```kusto
{kql}
```

Reply "yes" to run it or "no" to cancel.
````

### 10. `Bot/SecurityAgentBot.cs`

Inject `IPendingApprovalStore` instead of `ConversationStateService`. Remove
`IsApprovalResponse`.

At the top of `OnMessageActivityAsync`, before the empty-text check, work out the turn:

- `caller` = `new AgentCaller(conversation id, Activity.From?.AadObjectId, Activity.From?.Name)`.
- **Card submit**: `Activity.Value` is not null and its `action` is `kql_approval`.
  Read `decision` and `proposalId`.
- **Typed decision**: otherwise, `ApprovalIntent.Parse(text)` is not `None` **and**
  `PeekAsync` finds a pending approval for this conversation.
- **Anything else**: a normal question.

Handling a decision (card or typed):

1. `PeekAsync`. If null: reply "There is no query waiting for approval. It may have
   expired or already been handled." and return.
2. Card submit only: if `proposalId` differs from the pending one, reply with the same
   message as step 1 and return (the card is stale).
3. If the pending `RequesterId` is not null and differs from the caller's `UserId`:
   reply "Only {RequesterName} can approve or cancel this query." and return. Do not
   remove the pending approval.
4. `TakeAsync`. If null (lost a race): return without replying.
5. Card submit only: replace the original card with `BuildResolvedCard` using
   `turnContext.UpdateActivityAsync` and `Activity.ReplyToId`. If the update throws, log
   a warning and continue.
6. Send a typing activity, call `ResumeAfterApprovalAsync(pending, approved)`, and handle
   the response exactly like a normal question's response (below).

Handling a normal question:

1. If text is empty: existing "Please send a text message…" reply.
2. `DeleteAsync` for this conversation (a new question abandons any pending query).
3. `RunAgentAsync(text, caller)`.

Handling any `AgentResponse`:

- If `Pending` is not null: `SaveAsync(Pending)`, then send `BuildRequestCard(Pending)`
  as an attachment. Do not also send the fallback text.
- Otherwise: existing `SendResponseAsync`.

Keep the existing try/catch and error reply around the agent call.

### 11. `Functions/SecurityAgentFunction.cs`

Request body gains an optional field:

```json
{ "question": "...", "conversationId": "...", "approval": { "proposalId": "...", "decision": "approve" } }
```

- With `approval`: `conversationId` is required (400 if missing). `decision` must be
  `approve` or `reject` (400 otherwise). `TakeAsync`; if null or `proposalId` differs,
  return 409 `{"error":"No matching query is awaiting approval."}` (if it differs, save
  it back before returning). Otherwise `ResumeAfterApprovalAsync`. `question` is ignored.
- Without `approval`: `question` is required as today. `DeleteAsync` for the
  conversation id if one was supplied, then `RunAgentAsync` with
  `new AgentCaller(conversationId, null, null)`.

Response body:

```json
{
  "message": "...",
  "conversationId": "...",
  "awaitingApproval": true,
  "proposal": { "proposalId": "...", "kql": "...", "explanation": "...", "estimatedScope": "..." }
}
```

`proposal` is `null` when not awaiting approval. When awaiting, `SaveAsync` before
responding.

### 12. Tests (`tests/SecurityAgent.Tests/`)

- `ApprovalIntentTests`: theory covering at least — approve: `yes`, `Yes!`, `yes please`,
  `ok run it`, `go ahead`; reject: `no`, `No, don't run it`, `cancel`; none: empty, null,
  `show me noncompliant devices`, `yesterday's sign-ins for alex`, `notify me`, a
  41-character string starting with "yes".
- `ChatHistorySerializerTests`: round-trip a list containing a user message, an assistant
  message with two tool calls and no text, two tool messages, and an assistant text
  message. Assert count, order, roles, tool call ids/names/arguments and text survive.
- `ApprovalCardBuilderTests`: request card JSON contains the KQL unmodified, two
  `Action.Submit` actions and the proposal id in both; resolved card has no actions.

## Out of scope

- Validating, limiting or rewriting the KQL before it runs (task 02).
- Result trimming and the hand-written schema reference in the prompt (task 02).
- Restricting who may talk to the bot (task 04).
- Remembering earlier questions in a conversation (task 08).
- README changes.

## Done when

- Build and tests pass; the `build` workflow is green.
- No reference to `execute_approved_hunting_query`, `_pendingQuery`, `IsApprovalResponse`
  or `ConversationStateService` remains anywhere in the repository.
- `AgentOrchestrator` calls the model in exactly one place.

## Manual test (repository owner, in Teams, after deploying the branch)

1. Ask: "Using a custom query, show 5 rows from DeviceInfo with only DeviceName and OSPlatform."
   Expect a card with the KQL and two buttons, and no second message.
2. Click **Run query**. Expect the card to lose its buttons and show "Approved by …",
   then an answer with rows.
3. Repeat step 1, then type `yes please`. Expect the query to run.
4. Repeat step 1, then click **Cancel**. Expect "Cancelled by …" and a short
   acknowledgement, with no query run (check the function log).
5. Repeat step 1, restart the Function App, then click **Run query**. Expect it to run.
6. Repeat step 1, click **Run query** twice quickly. Expect one answer.
7. Repeat step 1, then ask an unrelated question. Expect a normal answer; clicking the
   old card's button afterwards gives "There is no query waiting for approval…".
