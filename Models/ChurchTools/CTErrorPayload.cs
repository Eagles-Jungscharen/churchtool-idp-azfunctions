using System.Text.Json.Serialization;

namespace EaglesJungscharen.CT.IDP.Models.ChurchTools;

public class CTErrorPayload
{
    [JsonPropertyName("message")]
    public string? Message { get; set; }

    [JsonPropertyName("translatedMessage")]
    public string? TranslatedMessage { get; set; }

    [JsonPropertyName("messageKey")]
    public string? MessageKey { get; set; }

    [JsonPropertyName("args")]
    public List<string>? Args { get; set; }

    [JsonPropertyName("errors")]
    public List<string>? Errors { get; set; }
}
