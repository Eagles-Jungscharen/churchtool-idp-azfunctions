using System.Text.Json.Serialization;

namespace EaglesJungscharen.CT.IDP.Models;

public class ClientInformationListResponse
{
    [JsonPropertyName("clients")]
    public required List<ClientInformationResponse> Clients { get; set; }
}
