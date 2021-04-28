namespace EaglesJungscharen.CT.IDP.Models {
    public class LoginResult {
        public CTLoginResponse CTLoginResponse {set;get;}
        public bool Error {set;get;}
        public string ErrorMessage {set;get;}
        public string SetCookieHeader {set;get;}
    }
}