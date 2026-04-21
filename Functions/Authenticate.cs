using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using EaglesJungscharen.CT.IDP.Models.ChurchTools;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Services;
using Microsoft.Azure.Functions.Worker;

namespace EaglesJungscharen.CT.IDP.Functions;

public class Authenticate(ICTLoginService loginService, IJWTService jwtService, ILogger<Authenticate> logger)
{
    private readonly ICTLoginService _loginService = loginService;
    private readonly IJWTService _jwtService = jwtService;
    private readonly ILogger<Authenticate> _logger = logger;

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

        LoginResult lr = await _loginService.DoLogin(username, password);
        if (!lr.Error)
        {
            var ctWhoami = await _loginService.GetWhoAmi(lr.SetCookieHeader!);
            if (ctWhoami == null)
            {
                _logger.LogWarning("ChurchTools hatte keine Benutzerdetails nach erfolgreichem Login zurückgegeben.");
                return new ObjectResult("Fehler beim Abrufen der Benutzerdetails von ChurchTools")
                {
                    StatusCode = StatusCodes.Status502BadGateway
                };
            }
            List<CTGroupContainer> groups = await _loginService.GetGroups(lr.SetCookieHeader!, ctWhoami.Id);
            List<string> scopes = groups.Select(gc => "ct_group_" + gc.Group?.DomainIdentifier).ToList();
            Tokens tokens = await _jwtService.BuildJWTToken(ctWhoami, scopes);
            return new OkObjectResult(tokens);
        }
        _logger.LogInformation("Result: {Error}", lr.Error);
        return new UnauthorizedResult();
    }
}

