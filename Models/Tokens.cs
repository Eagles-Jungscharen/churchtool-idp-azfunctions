using Newtonsoft.Json;
namespace EaglesJungscharen.CT.IDP.Models {

    public class Tokens {
        public static Tokens BuildTokens(string idToken, string accessToken, string refreshToken, int expiresIn) {
            var tokens = new Tokens
            {
                IdToken = idToken,
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresIn = expiresIn
            };
            return tokens;
        }
        [JsonProperty("id_token")]
        public string IdToken { get; set; } = string.Empty;
        [JsonProperty("access_token")]
        public string AccessToken { get; set; } = string.Empty;
        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; } = string.Empty;
        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }
        [JsonProperty("token_type")]
        public readonly string TokenType = "Bearer";
    }
}