using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using EaglesJungscharen.CT.IDP.Services;
using Microsoft.Azure.Functions.Worker;
using EaglesJungscharen.CT.IDP.Models;

namespace EaglesJungscharen.CT.IDP.Functions;

public class GetPublicKeys(IJWKService jwkService)
{
    private readonly IJWKService _jwkService = jwkService;

    [Function("well-known")]
    public IActionResult Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", "get", Route = "jwks.json")] HttpRequest req)
    {
        var jwkKeys = _jwkService.GetPublicKeys();
        var response = new PublicKeyResponse()
        {
            Keys = [.. jwkKeys]
        };
        return new OkObjectResult(response);
    }
}

