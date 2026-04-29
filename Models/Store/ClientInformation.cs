namespace EaglesJungscharen.CT.IDP.Models.Store;
public class ClientInformation
{
    public required string ClientId { get; set; }
    public required List<string> RedirectUris { get; set; }
}