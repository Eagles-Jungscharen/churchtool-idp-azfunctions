using Newtonsoft.Json;

namespace EaglesJungscharen.CT.IDP.Models;

public class RefreshRequest
{
    [JsonProperty("refreshToken")]
    public required string RefreshToken { get; set; }
}
