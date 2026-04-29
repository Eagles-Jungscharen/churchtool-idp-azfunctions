using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Models.ChurchTools;
using EaglesJungscharen.CT.IDP.Services;

namespace EaglesJungscharen.CT.IDP.Functions;

public class Login(ICTLoginService loginService, IJWTService jwtService, ILogger<Login> logger, UserTokenService userTokenService, IAuthorizationRequestService authorizationRequestService, IAuthorizationCodeService authorizationCodeService)
{
    private readonly ICTLoginService _loginService = loginService;
    private readonly IJWTService _jwtService = jwtService;
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
            return new BadRequestObjectResult("Kein gültiges Login-Objekt übergeben");
        }

        string? username = loginRequest.Username;
        string? password = loginRequest.Password;
        string? authenticationRequestId = loginRequest.AuthenticationRequestId;

        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            return new BadRequestObjectResult("Kein Benutzername oder Passwort übergeben");
        }

        if (string.IsNullOrEmpty(authenticationRequestId))
        {
            return new BadRequestObjectResult("Keine AuthenticationRequestId übergeben");
        }

        var authorizationRequest = await _authorizationRequestService.GetAuthorizationRequestByIdAsync(authenticationRequestId);
        if (authorizationRequest == null)
        {
            return new BadRequestObjectResult("Ungültige AuthenticationRequestId");
        }

        if (DateTime.UtcNow - authorizationRequest.CreatedAt > TimeSpan.FromMinutes(5))
        {
            return new BadRequestObjectResult("AuthorizationRequest abgelaufen");
        }

        LoginResult loginResult = await _loginService.DoLogin(username, password);
        if (!loginResult.Error)
        {
            var ctWhoami = await _loginService.GetWhoAmi(loginResult.SetCookieHeader!);
            if (ctWhoami == null)
            {
                _logger.LogWarning("ChurchTools returned no user details after successful login.");
                return new ObjectResult("Fehler beim Abrufen der Benutzerdetails von ChurchTools")
                {
                    StatusCode = StatusCodes.Status502BadGateway
                };
            }
            List<CTGroupContainer> groups = await _loginService.GetGroups(loginResult.SetCookieHeader!, ctWhoami.Id);
            List<string> scopes = [.. groups.Select(gc => "ct_group_" + gc.Group?.DomainIdentifier)];
            var loginToken = await _loginService.GetLoginToken(loginResult.SetCookieHeader!, ctWhoami.Id);
            var stRef = await _userTokenService.StoreToken(loginResult.SetCookieHeader!, loginToken);

            var authorizationCode = await _authorizationCodeService.StoreAuthorizationCodeAsync(ctWhoami, scopes, stRef, authorizationRequest);
            return new RedirectResult($"{authorizationRequest.CallbackUrl}?code={Uri.EscapeDataString(authorizationCode.Id)}&state={Uri.EscapeDataString(authorizationRequest.State)}");
        }

        _logger.LogInformation("OIDC login failed: {Error}", loginResult.Error);
        return new UnauthorizedResult();
    }
}
