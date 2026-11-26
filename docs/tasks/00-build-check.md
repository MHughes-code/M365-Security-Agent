# 00 — Build check and test project

Branch: `task/00-build-check`

## Goal

Every pull request is built and tested automatically, and there is a test project that
later tasks can add to. No application behaviour changes.

## Changes

### 1. Test project

Create `tests/SecurityAgent.Tests/SecurityAgent.Tests.csproj`:

- xUnit test project, same `TargetFramework` as `SecurityAgent.csproj`, nullable and
  implicit usings enabled.
- Packages: `Microsoft.NET.Test.Sdk`, `xunit`, `xunit.runner.visualstudio` (current stable
  versions). This is the only place this task may add packages.
- `ProjectReference` to `../../SecurityAgent.csproj`.
- One test, `SmokeTests.FormatterLeavesPlainTextReadable`, that calls
  `SecurityAgent.Bot.MessageFormatter.EnhanceMessage("hello")` and asserts the result is
  not null or empty. Its purpose is to prove the reference and the runner work.

Add the test project to `SecurityAgent.sln`.

### 2. Keep the test folder out of the main project

`SecurityAgent.csproj` sits at the repository root, so its default globbing would compile
the test sources. Add to `SecurityAgent.csproj`:

```xml
<ItemGroup>
  <Compile Remove="tests/**" />
  <Content Remove="tests/**" />
  <None Remove="tests/**" />
</ItemGroup>
```

Make no other change to `SecurityAgent.csproj`.

### 3. GitHub Actions workflow

Create `.github/workflows/build.yml`:

- Name: `build`.
- Triggers: `pull_request` (all branches) and `push` to `main`.
- `permissions: contents: read`.
- One job on `ubuntu-latest` with these steps:
  1. `actions/checkout` (current major version).
  2. `actions/setup-dotnet` (current major version) with the SDK matching the project's
     target framework (`9.0.x` today).
  3. `dotnet restore SecurityAgent.sln`
  4. `dotnet build SecurityAgent.sln --configuration Release --no-restore`
  5. `dotnet test SecurityAgent.sln --configuration Release --no-build`

No secrets, no deployment, no caching.

### 4. Ignore file

Append to `.gitignore`: `TestResults/`.

## Out of scope

- Changing the target framework or any existing package version.
- Fixing warnings.
- Any change under `Bot/`, `Functions/`, `Services/`, `Config/`, `Models/`.

## If the existing code does not build

Fix only what is required to get zero build errors, with the smallest possible edit, and
list each fix under "Questions and deviations". Do not fix warnings.

## Done when

- `dotnet build` and `dotnet test` succeed locally from the repository root.
- The `build` workflow runs on the pull request and passes.
- `git diff main --stat` shows only: `.github/workflows/build.yml`, `.gitignore`,
  `SecurityAgent.csproj`, `SecurityAgent.sln`, and files under `tests/`.
