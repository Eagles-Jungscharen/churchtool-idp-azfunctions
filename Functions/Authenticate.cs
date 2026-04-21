using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using EaglesJungscharen.CT.IDP.Models.ChurchTools;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Services;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Net.Http.Headers;

namespace EaglesJungscharen.CT.IDP.Functions;

public class Authenticate(ICTLoginService loginService, IJWTService jwtService, ILogger<Authenticate> logger, UserTokenService userTokenService)
{
    private readonly ICTLoginService _loginService = loginService;
    private readonly IJWTService _jwtService = jwtService;
    private readonly ILogger<Authenticate> _logger = logger;
    private readonly UserTokenService _userTokenService = userTokenService;

    [Function("authenticate")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req)
    {
        _logger.LogInformation("Login requested");
        var loginRequest = await req.ReadFromJsonAsync<LoginRequest>();

        if (loginRequest == null)
        {
            return new BadRequestObjectResult("Kein gültiges Login-Objekt übergeben");
        }

        string? username = loginRequest.Username;
        string? password = loginRequest.Password;
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            return new BadRequestObjectResult("Kein Benutzername oder Passwort übergeben");
        }

        LoginResult loginResult = await _loginService.DoLogin(username, password);
        if (!loginResult.Error)
        {
            var ctWhoami = await _loginService.GetWhoAmi(loginResult.SetCookieHeader!);
            if (ctWhoami == null)
            {
                _logger.LogWarning("ChurchTools hatte keine Benutzerdetails nach erfolgreichem Login zurückgegeben.");
                return new ObjectResult("Fehler beim Abrufen der Benutzerdetails von ChurchTools")
                {
                    StatusCode = StatusCodes.Status502BadGateway
                };
            }
            List<CTGroupContainer> groups = await _loginService.GetGroups(loginResult.SetCookieHeader!, ctWhoami.Id);
            List<string> scopes = [.. groups.Select(gc => "ct_group_" + gc.Group?.DomainIdentifier)];
            var loginToken = await _loginService.GetLoginToken(loginResult.SetCookieHeader!, ctWhoami.Id);
            var extRef = await _userTokenService.StoreToken(loginResult.SetCookieHeader!, loginToken);
            Tokens tokens = await _jwtService.BuildJWTToken(ctWhoami, scopes, extRef);
            return new OkObjectResult(tokens);
        }
        _logger.LogInformation("Result: {Error}", loginResult.Error);
        return new UnauthorizedResult();
    }
}

