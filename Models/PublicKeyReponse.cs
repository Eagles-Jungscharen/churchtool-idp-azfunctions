using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace EaglesJungscharen.CT.IDP.Models;

public class PublicKeyResponse
{
    [JsonProperty("keys")]
    public required List<JsonWebKey> Keys { get; set; }
}
