using System.Text.Json.Serialization;
namespace EaglesJungscharen.CT.IDP.Models {

    public class Tokens {
        public static Tokens BuildTokens(string idToken, string accessToken, string refreshToken, int expiresIn, List<string>? scopes = null) {
            var tokens = new Tokens
            {
                IdToken = idToken,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresIn = expiresIn,
                Scope = scopes != null && scopes.Count > 0 ? string.Join(" ", scopes) : "openid"
            };
            return tokens;
        }
        [JsonPropertyName("id_token")]
        public string IdToken { get; set; } = string.Empty;
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = string.Empty;
        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; } = string.Empty;
        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
        [JsonPropertyName("token_type")]
        public readonly string TokenType = "Bearer";
        [JsonPropertyName("scope")]
        public string Scope { get; set; } = "openid";
    }
}