using System.Text.Json.Serialization;

namespace EaglesJungscharen.CT.IDP.Models.ChurchTools;

public class CTGroup
{
    [JsonPropertyName("domainIdentifier")]
    public int DomainIdentifier { get; set; }
    [JsonPropertyName("title")]
    public string? Title { get; set; }
    [JsonPropertyName("domainIdentifierString")]
    public string? DomainIdentifierString { get; set; }
}
public class CTGroupContainer
{
    [JsonPropertyName("group")]
    public CTGroup? Group { get; set; }
}
