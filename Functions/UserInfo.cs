using System.IdentityModel.Tokens.Jwt;
using EaglesJungscharen.CT.IDP.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace EaglesJungscharen.CT.IDP.Functions;

/// <summary>
/// OpenID Connect UserInfo-Endpoint gemäß OIDC Core 1.0 Section 5.3
/// Liefert Claims des authentifizierten Nutzers auf Basis des Access Tokens
/// </summary>
public class UserInfo(ILogger<UserInfo> logger)
{
    private readonly ILogger<UserInfo> _logger = logger;

    [Function("userinfo")]
    public IActionResult Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = "oidc/userinfo")] HttpRequest req)
    {
        _logger.LogInformation("UserInfo endpoint requested");

        // Bearer Token aus Authorization-Header extrahieren
        string? authHeader = req.Headers.Authorization;
        if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return new UnauthorizedObjectResult(new ErrorRecord
            {
                Error = "Kein gültiger Bearer Token im Authorization-Header",
                ErrorNumber = ErrorCodes.UserInfoMissingToken
            });
        }

        string accessToken = authHeader["Bearer ".Length..].Trim();
        JwtSecurityToken? jwt;
        try
        {
            var handler = new JwtSecurityTokenHandler();
            jwt = handler.ReadJwtToken(accessToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Invalid access token received at userinfo endpoint: {Message}", ex.Message);
            return new UnauthorizedObjectResult(new ErrorRecord
            {
                Error = "Ungültiger Access Token",
                ErrorNumber = ErrorCodes.UserInfoInvalidToken
            });
        }

        // Standard OIDC Claims aus dem JWT extrahieren und zurückgeben
        var firstName = jwt.Claims.FirstOrDefault(c => c.Type == "firstname")?.Value ?? "";
        var lastName = jwt.Claims.FirstOrDefault(c => c.Type == "lastname")?.Value ?? "";
        var name = $"{firstName} {lastName}".Trim();

        var claims = new Dictionary<string, object?>
        {
            ["sub"] = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value,
            ["name"] = string.IsNullOrWhiteSpace(name) ? null : name,
            ["given_name"] = string.IsNullOrWhiteSpace(firstName) ? null : firstName,
            ["family_name"] = string.IsNullOrWhiteSpace(lastName) ? null : lastName,
            ["email"] = jwt.Claims.FirstOrDefault(c => c.Type == "email")?.Value,
            ["st_ref"] = jwt.Claims.FirstOrDefault(c => c.Type == "st_ref")?.Value,
        };

        var scopes = jwt.Claims.Where(c => c.Type == "scopes").Select(c => c.Value).ToList();
        if (scopes.Count > 0)
        {
            claims["scopes"] = scopes;
        }

        // Leere Claims nicht zurückgeben
        var filteredClaims = claims
            .Where(kvp => kvp.Value != null)
            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

        return new OkObjectResult(filteredClaims);
    }
}
