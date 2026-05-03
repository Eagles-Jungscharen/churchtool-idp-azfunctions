using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Services;
using Microsoft.Azure.Functions.Worker;

namespace EaglesJungscharen.CT.IDP.Functions;

public class UpdateClientInformation(IClientInformationService clientInformationService, ILogger<UpdateClientInformation> logger)
{
    private readonly IClientInformationService _clientInformationService = clientInformationService;
    private readonly ILogger<UpdateClientInformation> _logger = logger;

    [Function("update-client")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "put", Route = "clients/{clientId}")] HttpRequest req,
        string clientId)
    {
        _logger.LogInformation("Update client requested: {ClientId}", clientId);
        
        var request = await req.ReadFromJsonAsync<UpdateClientInformationRequest>();

        if (request == null)
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Kein gültiges Request-Objekt übergeben",
                ErrorNumber = ErrorCodes.ClientManagementInvalidRequestObject
            });
        }

        // Mindestens ein Feld muss angegeben werden
        if (request.Name == null && request.Owner == null && request.RedirectUris == null)
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Mindestens ein Feld muss für Update angegeben werden",
                ErrorNumber = ErrorCodes.ClientManagementNoFieldsToUpdate
            });
        }

        // Validierung der RedirectUris falls angegeben
        if (request.RedirectUris != null)
        {
            if (request.RedirectUris.Count == 0)
            {
                return new BadRequestObjectResult(new ErrorRecord
                {
                    Error = "RedirectUris darf nicht leer sein",
                    ErrorNumber = ErrorCodes.ClientManagementMissingRedirectUris
                });
            }

            // Temporäres ClientInformation-Objekt für Validierung
            var tempClient = new Models.Store.ClientInformation
            {
                ClientId = clientId,
                Name = "temp",
                Owner = "temp",
                RedirectUris = request.RedirectUris
            };

            var validationResult = _clientInformationService.ValidateEntry(tempClient);
            if (!validationResult.IsValid)
            {
                return new BadRequestObjectResult(new ErrorRecord
                {
                    Error = string.Join("; ", validationResult.Errors),
                    ErrorNumber = ErrorCodes.ClientManagementMissingRedirectUris
                });
            }
        }

        // Client aktualisieren
        var updated = await _clientInformationService.UpdateClientInformationAsync(
            clientId, 
            request.Name, 
            request.Owner, 
            request.RedirectUris);

        if (updated == null)
        {
            return new NotFoundObjectResult(new ErrorRecord
            {
                Error = "Client nicht gefunden",
                ErrorNumber = ErrorCodes.ClientManagementClientNotFound
            });
        }

        _logger.LogInformation("Client updated: {ClientId}", updated.ClientId);

        // Response erstellen
        var response = new ClientInformationResponse
        {
            ClientId = updated.ClientId,
            Name = updated.Name,
            Owner = updated.Owner,
            RedirectUris = updated.RedirectUris
        };

        return new OkObjectResult(response);
    }
}
