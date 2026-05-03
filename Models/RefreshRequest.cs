using System.Text.Json.Serialization;

namespace EaglesJungscharen.CT.IDP.Models;

public class RefreshRequest
{
    [JsonPropertyName("refreshToken")]
    public required string RefreshToken { get; set; }
}
