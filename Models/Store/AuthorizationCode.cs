
namespace EaglesJungscharen.CT.IDP.Models.Store;

public class AuthorizationCode
{
    public required string Id { get; set; }

    public int UserId { get; set; }

    public string? FirstName { get; set; }

    public string? LastName { get; set; }

    public string? Email { get; set; }
    
    public List<string> Scopes { get; set; } = new();

    public string? CodeChallenge { get; set; }

    public string? CodeChallengeMethod { get; set; }
    public string? StRef { get; set; }

    public DateTime CreatedAt { get; set; }
}
