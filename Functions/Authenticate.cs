using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using EaglesJungscharen.CT.IDP.Models.ChurchTools;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Services;
using Microsoft.Azure.Functions.Worker;
using Microsoft.AspNetCore.Http.HttpResults;

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

        string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
        dynamic? data = JsonConvert.DeserializeObject(requestBody);
        if (data == null)
        {
            return new BadRequestObjectResult("No Payload available");
        }

        string? username = data.username;
        string? password = data.password;
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            return new BadRequestObjectResult("Kein Benutername oder Passwort übergeben");
        }

        LoginResult lr = await _loginService.DoLogin(username, password);
        _logger.LogInformation("Result: {Error}", lr.Error);

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
        return new UnauthorizedResult();
    }
}

