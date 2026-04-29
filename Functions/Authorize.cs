using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EaglesJungscharen.CT.IDP.Functions;

public class Authorize(ILogger<Authorize> logger, IOptions<ServiceConfiguration> serviceConfiguration, IClientInformationService clientInformationService, IAuthorizationRequestService authorizationRequestService)
{
    private readonly ILogger<Authorize> _logger = logger;
    private readonly ServiceConfiguration _serviceConfiguration = serviceConfiguration.Value;
    private readonly IClientInformationService _clientInformationService = clientInformationService;
    private readonly IAuthorizationRequestService _authorizationRequestService = authorizationRequestService;

    [Function("authorize")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "oidc/authorize")] HttpRequest req)
    {
        _logger.LogInformation("Authorize requested");

        string? responseType = req.Query["response_type"];
        string? clientId = req.Query["client_id"];
        string? redirectUri = req.Query["redirect_uri"];
        string? codeChallenge = req.Query["code_challenge"];
        string? codeChallengeMethod = req.Query["code_challenge_method"];
        string? state = req.Query["state"];

        if (string.IsNullOrWhiteSpace(responseType) ||
            string.IsNullOrWhiteSpace(clientId) ||
            string.IsNullOrWhiteSpace(redirectUri) ||
            string.IsNullOrWhiteSpace(codeChallenge) ||
            string.IsNullOrWhiteSpace(codeChallengeMethod) ||
            string.IsNullOrWhiteSpace(state))
        {
            return new BadRequestObjectResult("Fehlende Pflichtparameter");
        }

        if (!responseType.Contains("code", StringComparison.OrdinalIgnoreCase))
        {
            return new BadRequestObjectResult("response_type muss 'code' enthalten");
        }

        var clientInformation = await _clientInformationService.GetClientInformationByIdAsync(clientId);
        if (clientInformation == null)
        {
            return new BadRequestObjectResult($"Unbekannte Client-ID '{clientId}'");
        }

        if (!clientInformation.RedirectUris.Contains(redirectUri, StringComparer.Ordinal))
        {
            return new BadRequestObjectResult($"Ungültige redirect_uri '{redirectUri}' für Client '{clientId}'");
        }

        var request = await _authorizationRequestService.StoreAuthorizationRequestAsync(codeChallenge, codeChallengeMethod, redirectUri, state);
        _logger.LogInformation("Authorization request stored for client {ClientId}", clientId);

        return new RedirectResult($"{_serviceConfiguration.LoginClientURL}?authorization_request_id={request.Id}", false);
    }
}