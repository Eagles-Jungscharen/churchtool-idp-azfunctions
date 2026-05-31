using System.Security.Cryptography;
using System.Text;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Models.ChurchTools;
using EaglesJungscharen.CT.IDP.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace EaglesJungscharen.CT.IDP.Functions;

public class Token(
    ILogger<Token> logger,
    IClientInformationService clientInformationService,
    IAuthorizationCodeService authorizationCodeService,
    IJWTService jwtService)
{
    private static readonly TimeSpan AuthorizationCodeLifetime = TimeSpan.FromMinutes(5);

    private readonly ILogger<Token> _logger = logger;
    private readonly IClientInformationService _clientInformationService = clientInformationService;
    private readonly IAuthorizationCodeService _authorizationCodeService = authorizationCodeService;
    private readonly IJWTService _jwtService = jwtService;

    [Function("token")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "oidc/token")] HttpRequest req)
    {
        _logger.LogInformation("OIDC token endpoint requested");

        if (!req.HasFormContentType)
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Content-Type muss 'application/x-www-form-urlencoded' sein",
                ErrorNumber = ErrorCodes.TokenInvalidContentType
            });
        }

        var form = await req.ReadFormAsync();
        string? grantType = form["grant_type"];
        string? clientId = form["client_id"];

        if (string.IsNullOrWhiteSpace(grantType))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Fehlende Pflichtparameter",
                ErrorNumber = ErrorCodes.TokenMissingParameters
            });
        }

        string issuer = $"{req.Scheme}://{req.Host.Value}/api/oidc";

        // Refresh Token Grant (RFC 6749, Section 6)
        if (string.Equals(grantType, "refresh_token", StringComparison.Ordinal))
        {
            return await HandleRefreshTokenGrant(form, clientId, issuer);
        }

        // Authorization Code Grant
        if (!string.Equals(grantType, "authorization_code", StringComparison.Ordinal))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "grant_type muss 'authorization_code' oder 'refresh_token' sein",
                ErrorNumber = ErrorCodes.TokenInvalidGrantType
            });
        }

        return await HandleAuthorizationCodeGrant(form, clientId, issuer);
    }

    private async Task<IActionResult> HandleRefreshTokenGrant(IFormCollection form, string? clientId, string issuer)
    {
        string? refreshToken = form["refresh_token"];

        if (string.IsNullOrWhiteSpace(refreshToken) || string.IsNullOrWhiteSpace(clientId))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Fehlende Pflichtparameter für refresh_token Grant",
                ErrorNumber = ErrorCodes.TokenMissingParameters
            });
        }

        var clientInformation = await _clientInformationService.GetClientInformationByIdAsync(clientId);
        if (clientInformation == null)
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = $"Unbekannte Client-ID '{clientId}'",
                ErrorNumber = ErrorCodes.TokenUnknownClientId
            });
        }

        _logger.LogInformation("Refresh token grant requested for client {ClientId}", clientId);
        var tokens = await _jwtService.UseRefreshTokenAsync(refreshToken, issuer, clientId);
        if (tokens == null)
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Ungültiger oder abgelaufener Refresh Token",
                ErrorNumber = ErrorCodes.TokenInvalidAuthorizationCode
            });
        }
        return new OkObjectResult(tokens);
    }

    private async Task<IActionResult> HandleAuthorizationCodeGrant(IFormCollection form, string? clientId, string issuer)
    {
        var tokenRequest = new TokenRequest
        {
            GrantType = form["grant_type"],
            Code = form["code"],
            CodeVerifier = form["code_verifier"],
            ClientId = clientId,
            RedirectUri = form["redirect_uri"]
        };

        if (string.IsNullOrWhiteSpace(tokenRequest.Code) ||
            string.IsNullOrWhiteSpace(tokenRequest.CodeVerifier) ||
            string.IsNullOrWhiteSpace(tokenRequest.ClientId) ||
            string.IsNullOrWhiteSpace(tokenRequest.RedirectUri))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Fehlende Pflichtparameter",
                ErrorNumber = ErrorCodes.TokenMissingParameters
            });
        }

        var clientInformation = await _clientInformationService.GetClientInformationByIdAsync(tokenRequest.ClientId);
        if (clientInformation == null)
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = $"Unbekannte Client-ID '{tokenRequest.ClientId}'",
                ErrorNumber = ErrorCodes.TokenUnknownClientId
            });
        }

        if (!clientInformation.RedirectUris.Contains(tokenRequest.RedirectUri, StringComparer.Ordinal))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = $"Ungültige redirect_uri '{tokenRequest.RedirectUri}' für Client '{tokenRequest.ClientId}'",
                ErrorNumber = ErrorCodes.TokenInvalidRedirectUri
            });
        }

        var authorizationCode = await _authorizationCodeService.GetAuthorizationCodeByIdAsync(tokenRequest.Code);
        if (authorizationCode == null)
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Ungültiger Authorization Code",
                ErrorNumber = ErrorCodes.TokenInvalidAuthorizationCode
            });
        }

        if (DateTime.UtcNow - authorizationCode.CreatedAt > AuthorizationCodeLifetime)
        {
            await _authorizationCodeService.DeleteAuthorizationCodeAsync(tokenRequest.Code);
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Authorization Code abgelaufen",
                ErrorNumber = ErrorCodes.TokenExpiredAuthorizationCode
            });
        }

        if (!string.IsNullOrWhiteSpace(authorizationCode.CallbackUrl) &&
            !string.Equals(authorizationCode.CallbackUrl, tokenRequest.RedirectUri, StringComparison.Ordinal))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "redirect_uri stimmt nicht mit der Authorisierungsanfrage überein",
                ErrorNumber = ErrorCodes.TokenRedirectUriMismatch
            });
        }

        if (!IsValidPkceS256(tokenRequest.CodeVerifier, authorizationCode.CodeChallengeMethod, authorizationCode.CodeChallenge))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Ungültiger code_verifier",
                ErrorNumber = ErrorCodes.TokenInvalidCodeVerifier
            });
        }

        if (string.IsNullOrWhiteSpace(authorizationCode.StRef))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Ungültiger Authorization Code",
                ErrorNumber = ErrorCodes.TokenInvalidAuthorizationCode
            });
        }

        var ctWhoami = new CTWhoami
        {
            Id = authorizationCode.UserId,
            FirstName = authorizationCode.FirstName,
            LastName = authorizationCode.LastName,
            Email = authorizationCode.Email
        };

        // audience = client_id (RFC: oidc-client-ts validates id_token.aud == client_id)
        string audience = tokenRequest.ClientId;
        var tokens = await _jwtService.BuildJWTToken(ctWhoami, authorizationCode.Scopes, authorizationCode.StRef, issuer, audience, authorizationCode.Nonce);
        await _authorizationCodeService.DeleteAuthorizationCodeAsync(tokenRequest.Code);

        return new OkObjectResult(tokens);
    }

    private static bool IsValidPkceS256(string codeVerifier, string? codeChallengeMethod, string? codeChallenge)
    {
        if (!string.Equals(codeChallengeMethod, "S256", StringComparison.Ordinal))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(codeChallenge))
        {
            return false;
        }

        var verifierBytes = Encoding.ASCII.GetBytes(codeVerifier);
        var hashedVerifier = SHA256.HashData(verifierBytes);
        var hashedVerifierBase64Url = Base64UrlEncoder.Encode(hashedVerifier);

        var expectedBytes = Encoding.ASCII.GetBytes(codeChallenge);
        var actualBytes = Encoding.ASCII.GetBytes(hashedVerifierBase64Url);

        return expectedBytes.Length == actualBytes.Length &&
               CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }
}

