using EaglesJungscharen.CT.IDP.Models.Store;
using GuedesPlace.AzureTools.Tables;

namespace EaglesJungscharen.CT.IDP.Services;

public interface IAuthorizationRequestService
{
    Task<AuthorizationRequest> StoreAuthorizationRequestAsync(string codeChallenge, string codeChallengeMethod, string callbackUrl, string state);
}

public class AuthorizationRequestService(ExtendedAzureTableClientService tableClientService) : IAuthorizationRequestService
{
    private readonly TypedAzureTableClient<AuthorizationRequest> _tableClient =
        tableClientService.GetTypedTableClient<AuthorizationRequest>();

    public async Task<AuthorizationRequest> StoreAuthorizationRequestAsync(string codeChallenge, string codeChallengeMethod, string callbackUrl, string state)
    {
        var authorizationRequest = new AuthorizationRequest
        {
            Id = Guid.NewGuid().ToString(),
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            CallbackUrl = callbackUrl,
            State = state
        };

        await _tableClient.InsertOrReplaceAsync(authorizationRequest.Id, "AUTH_REQUEST", authorizationRequest);
        return authorizationRequest;
    }
}
