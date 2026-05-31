using EaglesJungscharen.CT.IDP.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace EaglesJungscharen.CT.IDP.Functions;

/// <summary>
/// OpenID Connect End-Session-Endpoint gemäß OIDC Session Management 1.0
/// Leitet nach dem Logout zum post_logout_redirect_uri weiter
/// </summary>
public class EndSession(ILogger<EndSession> logger)
{
    private readonly ILogger<EndSession> _logger = logger;

    [Function("end-session")]
    public IActionResult Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = "oidc/end_session")] HttpRequest req)
    {
        _logger.LogInformation("End session endpoint requested");

        // post_logout_redirect_uri aus Query oder Form lesen
        string? postLogoutRedirectUri = req.Query["post_logout_redirect_uri"];

        // Wenn kein Redirect-URI angegeben, einfach 200 OK zurückgeben
        if (string.IsNullOrWhiteSpace(postLogoutRedirectUri))
        {
            return new OkResult();
        }

        // Nur https:// und http://localhost als Redirect-Ziele erlaubt (Sicherheit)
        if (!postLogoutRedirectUri.StartsWith("https://", StringComparison.OrdinalIgnoreCase) &&
            !postLogoutRedirectUri.StartsWith("http://localhost", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Invalid post_logout_redirect_uri rejected: {Uri}", postLogoutRedirectUri);
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Ungültige post_logout_redirect_uri",
                ErrorNumber = ErrorCodes.EndSessionInvalidRedirectUri
            });
        }

        return new RedirectResult(postLogoutRedirectUri, false);
    }
}
