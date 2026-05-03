namespace EaglesJungscharen.CT.IDP.Models.Store;

public class PrivateKey
{
    public required string KeyId { get; set; }
    public required string PrivateKeyValue { get; set; }
    public required string PublicKeyId { get; set; }
    public required DateTime Expires { get; set; }
}