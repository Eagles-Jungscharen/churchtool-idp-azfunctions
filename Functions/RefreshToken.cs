using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Services;
using Microsoft.Azure.Functions.Worker;

namespace EaglesJungscharen.CT.IDP.Functions;

public class RefreshToken(IJWTService jwtService, ILogger<RefreshToken> logger)
{
    private readonly IJWTService _jwtService = jwtService;
    private readonly ILogger<RefreshToken> _logger = logger;

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
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Keine Nutzlast verfügbar",
                ErrorNumber = ErrorCodes.RefreshTokenNoPayload
            });
        }
        if (string.IsNullOrEmpty(refreshRequest.RefreshToken))
        {
            return new BadRequestObjectResult(new ErrorRecord
            {
                Error = "Kein refreshToken übermittelt",
                ErrorNumber = ErrorCodes.RefreshTokenMissingToken
            });
        }

        string refreshToken = refreshRequest.RefreshToken;
        string accessTokenShort = accessToken.Substring(7);
        _logger.LogInformation("Access token: {AccessToken}", accessTokenShort);

        if (await _jwtService.CheckRefreshToken(refreshToken, accessTokenShort))
        {
            Tokens tokens = await _jwtService.CreateNewTokenFromAccessToken(accessTokenShort);
            return new OkObjectResult(tokens);
        }
        return new BadRequestObjectResult(new ErrorRecord
        {
            Error = "Refresh und Access Token Kombination ungültig",
            ErrorNumber = ErrorCodes.RefreshTokenInvalidCombination
        });
    }
}

