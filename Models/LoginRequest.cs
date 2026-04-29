using System.Text.Json.Serialization;

namespace EaglesJungscharen.CT.IDP.Models;

public class LoginRequest
{
    [JsonPropertyName("username")]
    public string? Username { get; set; }
    [JsonPropertyName("password")]
    public string? Password { get; set; }
    [JsonPropertyName("authentication_request_id")]
    public string? AuthenticationRequestId { get; set; }
}
