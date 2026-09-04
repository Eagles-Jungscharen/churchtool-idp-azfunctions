namespace EaglesJungscharen.CT.IDP.Models.ChurchTools;
using System.Text.Json.Serialization;
public class CTLoginTokenResponse
{
    [JsonPropertyName("personId")]
    public int PersonId { get; set; }
    [JsonPropertyName("token")]
    public string? Token { get; set; }
}