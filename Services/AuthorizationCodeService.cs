using EaglesJungscharen.CT.IDP.Models.ChurchTools;
using EaglesJungscharen.CT.IDP.Models.Store;
using GuedesPlace.AzureTools.Tables;

namespace EaglesJungscharen.CT.IDP.Services;

public interface IAuthorizationCodeService
{
    Task<AuthorizationCode> StoreAuthorizationCodeAsync(CTWhoami whoami, List<string> scopes, string stRef, AuthorizationRequest authorizationRequest);
}

public class AuthorizationCodeService(ExtendedAzureTableClientService tableClientService) : IAuthorizationCodeService
{
    private readonly TypedAzureTableClient<AuthorizationCode> _tableClient =
        tableClientService.GetTypedTableClient<AuthorizationCode>();

    public async Task<AuthorizationCode> StoreAuthorizationCodeAsync(CTWhoami whoami, List<string> scopes, string stRef, AuthorizationRequest authorizationRequest)
    {
        var authorizationCode = new AuthorizationCode
        {
            Id = Guid.NewGuid().ToString(),
            UserId = whoami.Id,
            FirstName = whoami.FirstName,
            LastName = whoami.LastName,
            Email = whoami.Email,
            Scopes = scopes,
            CodeChallenge = authorizationRequest.CodeChallenge,
            CodeChallengeMethod = authorizationRequest.CodeChallengeMethod,
            StRef = stRef,
            CreatedAt = DateTime.UtcNow
        };

        await _tableClient.InsertOrReplaceAsync(authorizationCode.Id, "AUTH_CODE", authorizationCode);
        return authorizationCode;
    }
}
