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
        var tokenRequest = new TokenRequest
        {
            GrantType = form["grant_type"],
            Code = form["code"],
            CodeVerifier = form["code_verifier"],
            ClientId = form["client_id"],
            RedirectUri = form["redirect_uri"]
        };

        if (string.IsNullOrWhiteSpace(tokenRequest.GrantType) ||
            string.IsNullOrWhiteSpace(tokenRequest.Code) ||
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

        if (!string.Equals(tokenRequest.GrantType, "authorization_code", StringComparison.Ordinal))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "grant_type muss 'authorization_code' sein",
                ErrorNumber = ErrorCodes.TokenInvalidGrantType
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

        var tokens = await _jwtService.BuildJWTToken(ctWhoami, authorizationCode.Scopes, authorizationCode.StRef);
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
