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

    /// <summary>
    /// ChurchTools liefert nach erfolgreichem Login keine Benutzerdetails
    /// </summary>
    public const int AuthenticateChurchToolsUserDetailsFailed = 2003;

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

    /// <summary>
    /// ChurchTools liefert nach erfolgreichem Login keine Benutzerdetails
    /// </summary>
    public const int LoginChurchToolsUserDetailsFailed = 5006;

    // Client Management (6000-6099)
    
    /// <summary>
    /// Kein gültiges Request-Objekt übergeben
    /// </summary>
    public const int ClientManagementInvalidRequestObject = 6001;
    
    /// <summary>
    /// ClientId fehlt oder ist leer
    /// </summary>
    public const int ClientManagementMissingClientId = 6002;
    
    /// <summary>
    /// Name fehlt oder ist leer
    /// </summary>
    public const int ClientManagementMissingName = 6003;
    
    /// <summary>
    /// Owner fehlt oder ist leer
    /// </summary>
    public const int ClientManagementMissingOwner = 6004;
    
    /// <summary>
    /// RedirectUris fehlt oder ist leer
    /// </summary>
    public const int ClientManagementMissingRedirectUris = 6005;
    
    /// <summary>
    /// Mindestens ein Feld muss für Update angegeben werden
    /// </summary>
    public const int ClientManagementNoFieldsToUpdate = 6006;
    
    /// <summary>
    /// Client nicht gefunden
    /// </summary>
    public const int ClientManagementClientNotFound = 6007;
}
