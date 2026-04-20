namespace EaglesJungscharen.CT.IDP.Models {
    public class LoginResult {
        public CTLoginResponse? CTLoginResponse { get; set; }
        public bool Error { get; set; }
        public string? ErrorMessage { get; set; }
        public string? SetCookieHeader { get; set; }
    }
}