using System.Text.Json.Serialization;

namespace EaglesJungscharen.CT.IDP.Models;

public class CreateClientInformationRequest
{
    [JsonPropertyName("clientId")]
    public string? ClientId { get; set; }
    
    [JsonPropertyName("name")]
    public string? Name { get; set; }
    
    [JsonPropertyName("owner")]
    public string? Owner { get; set; }
    
    [JsonPropertyName("redirectUris")]
    public List<string>? RedirectUris { get; set; }
}
