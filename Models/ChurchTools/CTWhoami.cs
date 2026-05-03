using System.Text.Json.Serialization;
namespace EaglesJungscharen.CT.IDP.Models.ChurchTools;

public class CTWhoami
{
    [JsonPropertyName("id")]
    public int Id { get; set; }
    [JsonPropertyName("firstName")]
    public string? FirstName { get; set; }
    [JsonPropertyName("lastName")]
    public string? LastName { get; set; }
    [JsonPropertyName("email")]
    public string? Email { get; set; }
}
