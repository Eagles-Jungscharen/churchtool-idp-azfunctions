using System.Text.Json.Serialization;

namespace EaglesJungscharen.CT.IDP.Models;

public class ClientInformationResponse
{
    [JsonPropertyName("clientId")]
    public required string ClientId { get; set; }
    
    [JsonPropertyName("name")]
    public required string Name { get; set; }
    
    [JsonPropertyName("owner")]
    public required string Owner { get; set; }
    
    [JsonPropertyName("redirectUris")]
    public required List<string> RedirectUris { get; set; }
}
