using System.Text.Json.Serialization;

namespace EaglesJungscharen.CT.IDP.Models.ChurchTools;

public class CTResponse<T>
{
    [JsonPropertyName("data")]
    public T? Data { get; set; }
}
