namespace EaglesJungscharen.CT.IDP.Models;

public class RefreshToken
{
    public required string RefreshTokenValue { get; set; }
    public required string AccessToken { get; set; }
    public required DateTime Expires { get; set; }
}
