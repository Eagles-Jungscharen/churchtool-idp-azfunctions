using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
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
            return new BadRequestObjectResult("Nix username or password");
        }

        LoginResult lr = await _loginService.DoLogin(username, password);
        _logger.LogInformation("Result: {Error}", lr.Error);

        if (!lr.Error)
        {
            CTWhoami cTWhoami = await _loginService.GetWhoAmi(lr.SetCookieHeader!);
            List<CTGroupContainer> groups = await _loginService.GetGroups(lr.SetCookieHeader!, cTWhoami.Id);
            List<string> scopes = groups.Select(gc => "ct_group_" + gc.Group?.DomainIdentifier).ToList();
            Tokens tokens = await _jwtService.BuildJWTToken(cTWhoami, scopes);
            return new OkObjectResult(tokens);
        }
        return new UnauthorizedResult();
    }
}

