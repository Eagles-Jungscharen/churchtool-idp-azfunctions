using EaglesJungscharen.CT.IDP.Models.ChurchTools;
using EaglesJungscharen.CT.IDP.Models.Store;
using GuedesPlace.AzureTools.Tables;

namespace EaglesJungscharen.CT.IDP.Services;

public interface IAuthorizationCodeService
{
    Task<AuthorizationCode> StoreAuthorizationCodeAsync(CTWhoami whoami, List<string> scopes, string stRef, AuthorizationRequest authorizationRequest);
    Task<AuthorizationCode?> GetAuthorizationCodeByIdAsync(string id);
    Task DeleteAuthorizationCodeAsync(string id);
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
            CallbackUrl = authorizationRequest.CallbackUrl,
            StRef = stRef,
            CreatedAt = DateTime.UtcNow
        };

        await _tableClient.InsertOrReplaceAsync(authorizationCode.Id, "AUTH_CODE", authorizationCode);
        return authorizationCode;
    }

    public async Task<AuthorizationCode?> GetAuthorizationCodeByIdAsync(string id)
    {
        var result = await _tableClient.GetByIdAsync(id, "AUTH_CODE");
        return result?.Entity;
    }

    public async Task DeleteAuthorizationCodeAsync(string id)
    {
        await _tableClient.DeleteEntityAsync(id, "AUTH_CODE");
    }
}
