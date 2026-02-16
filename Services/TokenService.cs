using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using SecurityAgent.Config;
using System.Collections.Concurrent;

namespace SecurityAgent.Services;

public class TokenService
{
    private readonly IConfidentialClientApplication _msalClient;
    private readonly ConcurrentDictionary<string, AuthenticationResult> _tokenCache = new();
    private readonly ILogger<TokenService> _logger;

    public TokenService(AgentConfiguration config, ILogger<TokenService> logger)
    {
        _logger = logger;

        _msalClient = ConfidentialClientApplicationBuilder
            .Create(config.ClientId)
            .WithClientSecret(config.ClientSecret)
            .WithAuthority(AzureCloudInstance.AzurePublic, config.TenantId)
            .Build();
    }

    /// <summary>
    /// Get an access token for the specified scope (Graph or Defender).
    /// Caches tokens and handles refresh automatically.
    /// </summary>
    public async Task<string> GetTokenAsync(string scope)
    {
        // Check cache first — MSAL handles expiry internally, but we also
        // cache the result to avoid unnecessary AcquireTokenForClient calls
        if (_tokenCache.TryGetValue(scope, out var cached) &&
            cached.ExpiresOn > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            return cached.AccessToken;
        }

        try
        {
            var result = await _msalClient
                .AcquireTokenForClient(new[] { scope })
                .ExecuteAsync();

            _tokenCache[scope] = result;
            _logger.LogDebug("Acquired token for scope {Scope}, expires {Expiry}",
                scope, result.ExpiresOn);

            return result.AccessToken;
        }
        catch (MsalException ex)
        {
            _logger.LogError(ex, "Failed to acquire token for scope {Scope}", scope);
            throw;
        }
    }
}
