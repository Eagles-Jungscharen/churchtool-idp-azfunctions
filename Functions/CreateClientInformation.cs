using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Models.Store;
using EaglesJungscharen.CT.IDP.Services;
using Microsoft.Azure.Functions.Worker;

namespace EaglesJungscharen.CT.IDP.Functions;

public class CreateClientInformation(IClientInformationService clientInformationService, ILogger<CreateClientInformation> logger)
{
    private readonly IClientInformationService _clientInformationService = clientInformationService;
    private readonly ILogger<CreateClientInformation> _logger = logger;

    [Function("create-client")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post", Route = "clients")] HttpRequest req)
    {
        _logger.LogInformation("Create client requested");
        
        var request = await req.ReadFromJsonAsync<CreateClientInformationRequest>();

        if (request == null)
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Kein gültiges Request-Objekt übergeben",
                ErrorNumber = ErrorCodes.ClientManagementInvalidRequestObject
            });
        }

        // Validierung der Pflichtfelder
        if (string.IsNullOrWhiteSpace(request.ClientId))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "ClientId fehlt oder ist leer",
                ErrorNumber = ErrorCodes.ClientManagementMissingClientId
            });
        }

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Name fehlt oder ist leer",
                ErrorNumber = ErrorCodes.ClientManagementMissingName
            });
        }

        if (string.IsNullOrWhiteSpace(request.Owner))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Owner fehlt oder ist leer",
                ErrorNumber = ErrorCodes.ClientManagementMissingOwner
            });
        }

        if (request.RedirectUris == null || request.RedirectUris.Count == 0)
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "RedirectUris fehlt oder ist leer",
                ErrorNumber = ErrorCodes.ClientManagementMissingRedirectUris
            });
        }

        // ClientInformation erstellen
        var clientInfo = new ClientInformation
        {
            ClientId = request.ClientId,
            Name = request.Name,
            Owner = request.Owner,
            RedirectUris = request.RedirectUris
        };

        // Validierung der RedirectUris
        var validationResult = _clientInformationService.ValidateEntry(clientInfo);
        if (!validationResult.IsValid)
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = string.Join("; ", validationResult.Errors),
                ErrorNumber = ErrorCodes.ClientManagementMissingRedirectUris
            });
        }

        // Client speichern
        var created = await _clientInformationService.CreateClientInformationAsync(clientInfo);

        _logger.LogInformation("Client created: {ClientId}", created.ClientId);

        // Response erstellen
        var response = new ClientInformationResponse
        {
            ClientId = created.ClientId,
            Name = created.Name,
            Owner = created.Owner,
            RedirectUris = created.RedirectUris
        };

        return new ObjectResult(response)
        {
            StatusCode = StatusCodes.Status201Created
        };
    }
}
