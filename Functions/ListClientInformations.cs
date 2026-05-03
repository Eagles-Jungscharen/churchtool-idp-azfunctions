using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Services;
using Microsoft.Azure.Functions.Worker;

namespace EaglesJungscharen.CT.IDP.Functions;

public class ListClientInformations(IClientInformationService clientInformationService, ILogger<ListClientInformations> logger)
{
    private readonly IClientInformationService _clientInformationService = clientInformationService;
    private readonly ILogger<ListClientInformations> _logger = logger;

    [Function("list-clients")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "clients")] HttpRequest req)
    {
        _logger.LogInformation("List clients requested");
        
        var clients = await _clientInformationService.GetAllClientInformationsAsync();

        var response = new ClientInformationListResponse
        {
            Clients = clients.Select(c => new ClientInformationResponse
            {
                ClientId = c.ClientId,
                Name = c.Name,
                Owner = c.Owner,
                RedirectUris = c.RedirectUris
            }).ToList()
        };

        _logger.LogInformation("Returning {Count} clients", response.Clients.Count);

        return new OkObjectResult(response);
    }
}
