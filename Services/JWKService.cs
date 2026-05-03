using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using EaglesJungscharen.CT.IDP.Models.Store;
using GuedesPlace.AzureTools.Tables;

namespace EaglesJungscharen.CT.IDP.Services;

public interface IJWKService
{
    Task<IEnumerable<JsonWebKey>> GetPublicKeys();
}

public class JWKService(ExtendedAzureTableClientService tableClientService) : IJWKService
{
    private readonly TypedAzureTableClient<PublicKey> _publicKeyTableClient =
        tableClientService.GetTypedTableClient<PublicKey>();


    public async Task<IEnumerable<JsonWebKey>> GetPublicKeys()
    {
        var allPK = await _publicKeyTableClient.GetAllAsync("ACCESS_PUBLIC");
        return allPK.Select(pke => GetJWKFromPK(pke.Entity));
    }

    public static JsonWebKey GetJWKFromPK(PublicKey pke)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportRSAPublicKey(Convert.FromBase64String(pke.PublicKeyValue!), out _);
        RsaSecurityKey rsaSecurity = new(rsa)
        {
            KeyId = pke.KeyId
        };

        return JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaSecurity);
    }
}
