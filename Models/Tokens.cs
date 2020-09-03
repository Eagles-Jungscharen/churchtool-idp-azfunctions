namespace EaglesJungscharen.CT.IDP.Models {

    public class Tokens {
        public static Tokens BuildTokens(string idToken,string accessToken,string refreshToken) {
            Tokens tokens = new Tokens();
            tokens.IdToken =idToken;
            tokens.AccessToken = accessToken;
            tokens.RefreshToken = refreshToken;
            return tokens;
        }
        public string IdToken {set;get;}
        public string AccessToken{set;get;}
        public string RefreshToken {set;get;}
    }
}