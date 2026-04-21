using System.Text.Json.Serialization;

namespace EaglesJungscharen.CT.IDP.Models.ChurchTools;

public class CTLoginResponse
{
    [JsonPropertyName("status")]
    public string? Status { get; set; }
    [JsonPropertyName("message")]
    public string? Message { get; set; }
    [JsonPropertyName("personId")]
    public int PersonId { get; set; }
}
