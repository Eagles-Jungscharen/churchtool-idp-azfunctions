namespace EaglesJungscharen.CT.IDP.Models.Store;

public class PublicKey
{
    public required string KeyId { get; set; }
    public required string PublicKeyValue { get; set; }
    public required DateTime Expires { get; set; }
}
