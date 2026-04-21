using Newtonsoft.Json;

namespace EaglesJungscharen.CT.IDP.Models.ChurchTools;

public class CTGroup
{
    [JsonProperty("domainIdentifier")]
    public int DomainIdentifier { get; set; }
    [JsonProperty("title")]
    public string? Title { get; set; }
    [JsonProperty("domainIdentifierString")]
    public string? DomainIdentifierString { get; set; }
}
public class CTGroupContainer
{
    [JsonProperty("group")]
    public CTGroup? Group { get; set; }
}
