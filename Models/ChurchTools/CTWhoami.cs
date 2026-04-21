using Newtonsoft.Json;

namespace EaglesJungscharen.CT.IDP.Models.ChurchTools;

public class CTWhoami
{
    [JsonProperty("id")]
    public int Id { get; set; }
    [JsonProperty("firstName")]
    public string? FirstName { get; set; }
    [JsonProperty("lastName")]
    public string? LastName { get; set; }
    [JsonProperty("email")]
    public string? Email { get; set; }
}
