namespace EaglesJungscharen.CT.IDP.Models;

/// <summary>
/// Zentrale Definition aller Fehlercodes für BadRequest-Antworten.
/// Gruppierung nach Function: 1000er (Authorize), 2000er (Authenticate), 3000er (Token), 4000er (RefreshToken), 5000er (Login).
/// </summary>
public static class ErrorCodes
{
    // Authorize.cs (1000-1099)
    
    /// <summary>
    /// Fehlende Pflichtparameter
    /// </summary>
    public const int AuthorizeMissingParameters = 1001;
    
    /// <summary>
    /// response_type muss 'code' enthalten
    /// </summary>
    public const int AuthorizeInvalidResponseType = 1002;
    
    /// <summary>
    /// Unbekannte Client-ID
    /// </summary>
    public const int AuthorizeUnknownClientId = 1003;
    
    /// <summary>
    /// Ungültige redirect_uri
    /// </summary>
    public const int AuthorizeInvalidRedirectUri = 1004;

    // Authenticate.cs (2000-2099)
    
    /// <summary>
    /// Kein gültiges Login-Objekt übergeben
    /// </summary>
    public const int AuthenticateInvalidLoginObject = 2001;
    
    /// <summary>
    /// Kein Benutzername oder Passwort übergeben
    /// </summary>
    public const int AuthenticateMissingCredentials = 2002;

    // Token.cs (3000-3099)
    
    /// <summary>
    /// Content-Type muss 'application/x-www-form-urlencoded' sein
    /// </summary>
    public const int TokenInvalidContentType = 3001;
    
    /// <summary>
    /// Fehlende Pflichtparameter
    /// </summary>
    public const int TokenMissingParameters = 3002;
    
    /// <summary>
    /// grant_type muss 'authorization_code' sein
    /// </summary>
    public const int TokenInvalidGrantType = 3003;
    
    /// <summary>
    /// Unbekannte Client-ID
    /// </summary>
    public const int TokenUnknownClientId = 3004;
    
    /// <summary>
    /// Ungültige redirect_uri
    /// </summary>
    public const int TokenInvalidRedirectUri = 3005;
    
    /// <summary>
    /// Ungültiger Authorization Code
    /// </summary>
    public const int TokenInvalidAuthorizationCode = 3006;
    
    /// <summary>
    /// Authorization Code abgelaufen
    /// </summary>
    public const int TokenExpiredAuthorizationCode = 3007;
    
    /// <summary>
    /// redirect_uri stimmt nicht mit der Authorisierungsanfrage überein
    /// </summary>
    public const int TokenRedirectUriMismatch = 3008;
    
    /// <summary>
    /// Ungültiger code_verifier
    /// </summary>
    public const int TokenInvalidCodeVerifier = 3009;

    // RefreshToken.cs (4000-4099)
    
    /// <summary>
    /// Keine Nutzlast verfügbar
    /// </summary>
    public const int RefreshTokenNoPayload = 4001;
    
    /// <summary>
    /// Kein refreshToken übermittelt
    /// </summary>
    public const int RefreshTokenMissingToken = 4002;
    
    /// <summary>
    /// Refresh und Access Token Kombination ungültig
    /// </summary>
    public const int RefreshTokenInvalidCombination = 4003;

    // Login.cs (5000-5099)
    
    /// <summary>
    /// Kein gültiges Login-Objekt übergeben
    /// </summary>
    public const int LoginInvalidLoginObject = 5001;
    
    /// <summary>
    /// Kein Benutzername oder Passwort übergeben
    /// </summary>
    public const int LoginMissingCredentials = 5002;
    
    /// <summary>
    /// Keine AuthenticationRequestId übergeben
    /// </summary>
    public const int LoginMissingAuthenticationRequestId = 5003;
    
    /// <summary>
    /// Ungültige AuthenticationRequestId
    /// </summary>
    public const int LoginInvalidAuthenticationRequestId = 5004;
    
    /// <summary>
    /// AuthorizationRequest abgelaufen
    /// </summary>
    public const int LoginExpiredAuthorizationRequest = 5005;
}
