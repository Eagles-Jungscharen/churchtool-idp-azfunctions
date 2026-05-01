using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Services;
using Microsoft.Azure.Functions.Worker;

namespace EaglesJungscharen.CT.IDP.Functions;

public class DeleteClientInformation(IClientInformationService clientInformationService, ILogger<DeleteClientInformation> logger)
{
    private readonly IClientInformationService _clientInformationService = clientInformationService;
    private readonly ILogger<DeleteClientInformation> _logger = logger;

    [Function("delete-client")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "delete", Route = "clients/{clientId}")] HttpRequest req,
        string clientId)
    {
        _logger.LogInformation("Delete client requested: {ClientId}", clientId);
        
        var deleted = await _clientInformationService.DeleteClientInformationAsync(clientId);

        if (!deleted)
        {
            return new NotFoundObjectResult(new ErrorRecord
            {
                Error = "Client nicht gefunden",
                ErrorNumber = ErrorCodes.ClientManagementClientNotFound
            });
        }

        _logger.LogInformation("Client deleted: {ClientId}", clientId);

        return new StatusCodeResult(StatusCodes.Status204NoContent);
    }
}
