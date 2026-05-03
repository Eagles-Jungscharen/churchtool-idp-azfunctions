namespace EaglesJungscharen.CT.IDP.Models.Store;

public class UserLoginTokens
{
    public required string Id { get; set; }
    public required string LoginToken { get; set; }
    public required string ChurchToolsCookie { get; set; }
    public required DateTime Expires { get; set; }
}