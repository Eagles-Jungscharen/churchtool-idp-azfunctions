using Newtonsoft.Json;
namespace EaglesJungscharen.CT.IDP.Models {

    public class Tokens {
        public static Tokens BuildTokens(string idToken,string accessToken,string refreshToken, int expiresIn) {
            Tokens tokens = new Tokens();
            tokens.IdToken =idToken;
            tokens.AccessToken = accessToken;
            tokens.RefreshToken = refreshToken;
            tokens.ExpiresIn = expiresIn;
            return tokens;
        }
        [JsonProperty("id_token")]
        public string IdToken {set;get;}
        [JsonProperty("access_token")]
        public string AccessToken{set;get;}
        [JsonProperty("refresh_token")]
        public string RefreshToken {set;get;}
        [JsonProperty("expires_in")]
        public int ExpiresIn {set;get;}
        [JsonProperty("token_type")]
        public readonly string TokenType ="Bearer";
    }
}