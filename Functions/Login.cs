using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Services;

namespace EaglesJungscharen.CT.IDP.Functions;

public class Login(ICTLoginService loginService, ILogger<Login> logger, UserTokenService userTokenService, IAuthorizationRequestService authorizationRequestService, IAuthorizationCodeService authorizationCodeService)
{
    private readonly ICTLoginService _loginService = loginService;
    private readonly ILogger<Login> _logger = logger;
    private readonly UserTokenService _userTokenService = userTokenService;
    private readonly IAuthorizationRequestService _authorizationRequestService = authorizationRequestService;
    private readonly IAuthorizationCodeService _authorizationCodeService = authorizationCodeService;

    [Function("login")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "login")] HttpRequest req)
    {
        _logger.LogInformation("OIDC login requested");
        var loginRequest = await req.ReadFromJsonAsync<LoginRequest>();

        if (loginRequest == null)
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Kein gültiges Login-Objekt übergeben",
                ErrorNumber = ErrorCodes.LoginInvalidLoginObject
            });
        }

        string? username = loginRequest.Username;
        string? password = loginRequest.Password;
        string? authenticationRequestId = loginRequest.AuthenticationRequestId;

        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Kein Benutzername oder Passwort übergeben",
                ErrorNumber = ErrorCodes.LoginMissingCredentials
            });
        }

        if (string.IsNullOrEmpty(authenticationRequestId))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Keine AuthenticationRequestId übergeben",
                ErrorNumber = ErrorCodes.LoginMissingAuthenticationRequestId
            });
        }

        var authorizationRequest = await _authorizationRequestService.GetAuthorizationRequestByIdAsync(authenticationRequestId);
        if (authorizationRequest == null)
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Ungültige AuthenticationRequestId",
                ErrorNumber = ErrorCodes.LoginInvalidAuthenticationRequestId
            });
        }

        if (DateTime.UtcNow - authorizationRequest.CreatedAt > TimeSpan.FromMinutes(5))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "AuthorizationRequest abgelaufen",
                ErrorNumber = ErrorCodes.LoginExpiredAuthorizationRequest
            });
        }

        LoginResult loginResult = await _loginService.DoLogin(username, password);
        if (!loginResult.Error)
        {
            var ctResponse = loginResult.CTLoginResponse;
            var ctWhoami = await _loginService.GetWhoAmi(ctResponse!.Token!, ctResponse.PersonId!);
            if (ctWhoami == null)
            {
                _logger.LogWarning("ChurchTools returned no user details after successful login.");
                return new ObjectResult(new ErrorRecord
                {
                    Error = "Fehler beim Abrufen der Benutzerdetails von ChurchTools",
                    ErrorNumber = ErrorCodes.LoginChurchToolsUserDetailsFailed
                })
                {
                    StatusCode = StatusCodes.Status502BadGateway
                };
            }
            // OIDC-Basis-Scopes aus dem AuthorizationRequest extrahieren und mit CT-Gruppen-Scopes zusammenführen
            var requestedOidcScopes = (authorizationRequest.Scope ?? "openid")
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Where(s => s is "openid" or "profile" or "email" or "offline_access")
                .ToList();
            if (!requestedOidcScopes.Contains("openid"))
                requestedOidcScopes.Insert(0, "openid");
            var stRef = await _userTokenService.StoreToken("--", ctResponse!.Token!);

            var authorizationCode = await _authorizationCodeService.StoreAuthorizationCodeAsync(ctWhoami, requestedOidcScopes, stRef, authorizationRequest);
            return new OkObjectResult(new {callback=$"{authorizationRequest.CallbackUrl}?code={Uri.EscapeDataString(authorizationCode.Id)}&state={Uri.EscapeDataString(authorizationRequest.State)}"});
        }

        _logger.LogInformation("OIDC login failed: {Error}", loginResult.Error);
        return new UnauthorizedResult();
    }
}
