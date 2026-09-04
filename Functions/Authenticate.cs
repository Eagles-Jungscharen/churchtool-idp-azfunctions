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
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Kein gültiges Login-Objekt übergeben",
                ErrorNumber = ErrorCodes.AuthenticateInvalidLoginObject
            });
        }

        string? username = loginRequest.Username;
        string? password = loginRequest.Password;
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Kein Benutzername oder Passwort übergeben",
                ErrorNumber = ErrorCodes.AuthenticateMissingCredentials
            });
        }

        LoginResult loginResult = await _loginService.DoLogin(username, password);
        if (!loginResult.Error)
        {
            var ctResponse = loginResult.CTLoginResponse;
            var ctWhoami = await _loginService.GetWhoAmi(ctResponse!.Token!, ctResponse.PersonId!);
            if (ctWhoami == null)
            {
                _logger.LogWarning("ChurchTools hatte keine Benutzerdetails nach erfolgreichem Login zurückgegeben.");
                return new ObjectResult(new ErrorRecord
                {
                    Error = "Fehler beim Abrufen der Benutzerdetails von ChurchTools",
                    ErrorNumber = ErrorCodes.AuthenticateChurchToolsUserDetailsFailed
                })
                {
                    StatusCode = StatusCodes.Status502BadGateway
                };
            }
            List<CTGroupContainer> groups = await _loginService.GetGroups(ctResponse!.Token!, ctWhoami.Id);
            List<string> scopes = [.. groups.Select(gc => "ct_group_" + gc.Group?.DomainIdentifier)];
            var extRef = await _userTokenService.StoreToken("--", ctResponse!.Token!);
            string issuer = $"{req.Scheme}://{req.Host.Value}/api/oidc";
            Tokens tokens = await _jwtService.BuildJWTToken(ctWhoami, scopes, extRef, issuer, "ct-auth");
            return new OkObjectResult(tokens);
        }
        _logger.LogInformation("Result: {Error}", loginResult.Error);
        return new UnauthorizedResult();
    }
}

