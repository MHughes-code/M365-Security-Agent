# AGENTS.md

Instructions for coding agents working in this repository.

## What this project is

An Azure Functions app (.NET isolated worker, C#) that exposes a Microsoft Teams bot and
HTTP endpoints. A user asks a security question; `AgentOrchestrator` runs an Azure OpenAI
tool-calling loop; tools call Microsoft Graph, Defender for Endpoint, Intune and Advanced
Hunting. A timer function also builds two HTML security reports.

The repository is **public**. It must stay generic: no tenant IDs, domains, organisation
names, user names, secrets or keys in code, comments, tests, docs or commit messages.

## Layout

| Path | Contents |
|---|---|
| `Program.cs` | DI registration and startup |
| `Functions/` | HTTP and timer triggers (`BotMessagesFunction`, `SecurityAgentFunction`, `ReportFunction`) |
| `Bot/` | Teams bot handler, Adaptive Card and text formatting |
| `Services/AgentOrchestrator.cs` | Model loop and the system prompt |
| `Services/ToolDefinitionService.cs` | Tool schemas given to the model |
| `Services/ToolExecutionService.cs` | Routes tool calls to services |
| `Services/AdvancedHuntingService.cs` | KQL templates and query execution |
| `Services/*ApiService.cs`, `IntuneService.cs` | Graph / Defender / Intune calls |
| `Services/ReportGeneratorService.cs`, `SharePointService.cs`, `EmailService.cs` | Reports |
| `docs/tasks/` | Task specs. One spec = one branch = one pull request |
| `tests/SecurityAgent.Tests/` | xUnit tests (created by task 00) |

## How work is assigned

1. You are given one spec file from `docs/tasks/`. Implement that spec and nothing else.
2. Work on a new branch named `task/NN-short-name` (matching the spec file name).
3. Open one pull request against `main`.

The spec is the source of truth. Where the spec and the existing code disagree, follow
the spec. Where the spec is silent or ambiguous, do **not** guess on anything that changes
behaviour: make the smallest reasonable choice, and list it under "Questions and
deviations" in the PR description.

## Commands

Run from the repository root.

```bash
dotnet restore SecurityAgent.sln
dotnet build SecurityAgent.sln --configuration Release --no-restore
dotnet test SecurityAgent.sln --configuration Release --no-build
```

The build must finish with zero errors, and tests must pass, before you open the PR.
You cannot run the app against a real tenant. Do not add code, tests or scripts that need
live Microsoft 365, Azure OpenAI or Azure Storage credentials.

## Rules

- Change only the files the spec names, plus files that must change for the build to pass.
  No drive-by refactors, renames, reformatting or comment rewrites.
- Do not add, remove or upgrade NuGet packages unless the spec says so.
- Do not change the target framework unless the spec says so.
- Do not edit KQL templates, the system prompt or tool definitions unless the spec says so.
- Never create, read, print or commit `local.settings.json`. Configuration examples go in
  `local.settings.template.json` with placeholder values.
- Never log secrets, tokens, or full message bodies. Existing truncated logging is fine.
- Match the existing style: file-scoped namespaces, nullable enabled, `System.Text.Json`
  for our own JSON, constructor injection, `ILogger<T>`.
- New logic that can be tested without network access gets xUnit tests.
- Keep public behaviour that the spec does not mention exactly as it is.

## Pull request description

Use this structure:

```
## Spec
docs/tasks/NN-name.md

## What changed
- file: one line on the change

## How it was verified
- build / test output summary

## Questions and deviations
- anything the spec did not cover, and what you chose
```

## Code review rules

- A change outside the spec's listed files needs a stated reason in the PR description.
- Flag any string that looks like a real tenant ID, domain, UPN, key or secret.
- Flag any new code path where model output is executed or sent without the checks the
  spec requires.
