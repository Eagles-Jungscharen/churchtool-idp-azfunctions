using EaglesJungscharen.CT.IDP.Models.Store;
using GuedesPlace.AzureTools.Tables;
using Microsoft.Extensions.Logging;

namespace EaglesJungscharen.CT.IDP.Services;

public class UserTokenService(ILogger<UserTokenService> logger, ExtendedAzureTableClientService tableClientService)
{
    private readonly ILogger<UserTokenService> _logger = logger;
    private readonly TypedAzureTableClient<UserLoginTokens> _tableClient = tableClientService.GetTypedTableClient<UserLoginTokens>();

    public async Task<string> StoreToken(string cookie, string token)
    {
        UserLoginTokens userLoginTokens = new()
        {
            Id = Guid.NewGuid().ToString(),
            ChurchToolsCookie = cookie,
            LoginToken = token,
            Expires = DateTime.UtcNow.AddSeconds(JWTService.Expires_In_PrivateKey)
        };
        await _tableClient.InsertOrReplaceAsync(userLoginTokens.Id, "USER_TOKEN", userLoginTokens);
        return userLoginTokens.Id;
    }
}