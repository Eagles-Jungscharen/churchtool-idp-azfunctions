namespace EaglesJungscharen.CT.IDP.Models.Store;
public class AuthorizationRequest
{
    public required string Id { get; set; }
    public required string CodeChallenge { get; set; }
    public required string CodeChallengeMethod { get; set; }
    public required string CallbackUrl { get; set; }
    public required string State { get; set; }
    public DateTime CreatedAt { get; set; }
}