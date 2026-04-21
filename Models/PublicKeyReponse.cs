using Microsoft.IdentityModel.Tokens;
using System.Text.Json.Serialization;

namespace EaglesJungscharen.CT.IDP.Models;

public class PublicKeyResponse
{
    [JsonPropertyName("keys")]
    public required List<JsonWebKey> Keys { get; set; }
}
