using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Functions.Worker;
using EaglesJungscharen.CT.IDP.Models;

namespace EaglesJungscharen.CT.IDP.Functions;

/// <summary>
/// OpenID Connect Discovery-Endpoint gemäß OpenID Connect Discovery 1.0 Spezifikation
/// Stellt Metadaten über den Identity Provider bereit, damit Clients automatisch konfiguriert werden können
/// </summary>
public class OpenIdConfigurationFunction
{
    [Function("openid-configuration")]
    public IActionResult Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "oidc/.well-known/openid-configuration")] HttpRequest req)
    {
        // Base-URL dynamisch aus Request ermitteln (funktioniert lokal und in Azure)
        var baseUrl = $"{req.Scheme}://{req.Host.Value}";
        var apiPrefix = "/api";

        var configuration = new OpenIdConfiguration
        {
            // Issuer - muss mit iss-Claim in JWTs übereinstimmen
            Issuer = $"{baseUrl}{apiPrefix}/oidc",

            // Erforderliche Endpoints
            AuthorizationEndpoint = $"{baseUrl}{apiPrefix}/oidc/authorize",
            TokenEndpoint = $"{baseUrl}{apiPrefix}/oidc/token",
            JwksUri = $"{baseUrl}{apiPrefix}/jwks.json",
            UserInfoEndpoint = $"{baseUrl}{apiPrefix}/oidc/userinfo",
            EndSessionEndpoint = $"{baseUrl}{apiPrefix}/oidc/end_session",

            // Erforderliche unterstützte Werte
            ResponseTypesSupported = ["code"],
            SubjectTypesSupported = ["public"],
            IdTokenSigningAlgValuesSupported = ["RS256"],

            // Empfohlene unterstützte Werte
            GrantTypesSupported = ["authorization_code", "refresh_token"],
            ScopesSupported = ["openid", "profile", "email", "offline_access"],
            ClaimsSupported = [
                "sub",
                "name",
                "given_name",
                "family_name",
                "email",
                "email_verified",
                "iat",
                "jti",
                "st_ref",
                "scopes"
            ],
            CodeChallengeMethodsSupported = ["S256"],
            TokenEndpointAuthMethodsSupported = ["none"],
            ResponseModesSupported = ["query"]
        };

        return new OkObjectResult(configuration);
    }
}
