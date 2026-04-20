using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Services;
using Microsoft.Azure.Functions.Worker;

namespace EaglesJungscharen.CT.IDP.Functions;

public class RefreshToken
{
    private readonly IJWTService _jwtService;
    private readonly ILogger<RefreshToken> _logger;

    public RefreshToken(IJWTService jwtService, ILogger<RefreshToken> logger)
    {
        _jwtService = jwtService;
        _logger = logger;
    }

    [Function("refresh")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req)
    {
        _logger.LogInformation("Refresh requested");

        var refreshRequest = await req.ReadFromJsonAsync<RefreshRequest>();
        string? accessToken = req.Headers.FirstOrDefault(header => header.Key == "Authorization").Value;

        if (accessToken == null || !accessToken.StartsWith("Bearer"))
        {
            return new UnauthorizedResult();
        }

        if (refreshRequest == null)
        {
            return new BadRequestObjectResult("No Payload available");
        }
        if (string.IsNullOrEmpty(refreshRequest.RefreshToken))
        {
            return new BadRequestObjectResult("No refreshToken submitted");
        }

        string refreshToken = refreshRequest.RefreshToken;
        string accessTokenShort = accessToken.Substring(7);
        _logger.LogInformation("Access token: {AccessToken}", accessTokenShort);

        if (_jwtService.CheckRefreshToken(refreshToken, accessTokenShort))
        {
            Tokens tokens = await _jwtService.CreateNewTokenFromAccessToken(accessTokenShort);
            return new OkObjectResult(tokens);
        }
        return new BadRequestObjectResult("Refresh and access Token Combination not valid");
    }
}

