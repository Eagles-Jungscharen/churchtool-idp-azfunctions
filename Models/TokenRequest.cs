namespace EaglesJungscharen.CT.IDP.Models;

public class TokenRequest
{
    public string? GrantType { get; set; }

    public string? Code { get; set; }

    public string? CodeVerifier { get; set; }

    public string? ClientId { get; set; }

    public string? RedirectUri { get; set; }
}
