using System.Text.Json.Serialization;

namespace EaglesJungscharen.CT.IDP.Models;

/// <summary>
/// OpenID Connect Discovery-Dokument gemäß RFC 8414 und OpenID Connect Discovery 1.0
/// </summary>
public class OpenIdConfiguration
{
    /// <summary>
    /// Issuer Identifier - MUSS mit dem iss-Claim in ausgestellten Tokens übereinstimmen
    /// </summary>
    [JsonPropertyName("issuer")]
    public required string Issuer { get; set; }

    /// <summary>
    /// URL des Authorization-Endpoints für OAuth 2.0 Authorization Code Flow
    /// </summary>
    [JsonPropertyName("authorization_endpoint")]
    public required string AuthorizationEndpoint { get; set; }

    /// <summary>
    /// URL des Token-Endpoints zum Austausch von Authorization Codes gegen Tokens
    /// </summary>
    [JsonPropertyName("token_endpoint")]
    public required string TokenEndpoint { get; set; }

    /// <summary>
    /// URL des JWKS-Endpoints mit öffentlichen Schlüsseln zur Token-Signaturprüfung
    /// </summary>
    [JsonPropertyName("jwks_uri")]
    public required string JwksUri { get; set; }

    /// <summary>
    /// Liste der unterstützten OAuth 2.0 response_type-Werte
    /// </summary>
    [JsonPropertyName("response_types_supported")]
    public required List<string> ResponseTypesSupported { get; set; }

    /// <summary>
    /// Liste der unterstützten Subject Identifier Types (public oder pairwise)
    /// </summary>
    [JsonPropertyName("subject_types_supported")]
    public required List<string> SubjectTypesSupported { get; set; }

    /// <summary>
    /// Liste der unterstützten Signaturalgorithmen für ID Tokens
    /// </summary>
    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public required List<string> IdTokenSigningAlgValuesSupported { get; set; }

    /// <summary>
    /// Liste der unterstützten OAuth 2.0 Grant Types
    /// </summary>
    [JsonPropertyName("grant_types_supported")]
    public List<string>? GrantTypesSupported { get; set; }

    /// <summary>
    /// Liste der unterstützten OAuth 2.0 Scopes
    /// </summary>
    [JsonPropertyName("scopes_supported")]
    public List<string>? ScopesSupported { get; set; }

    /// <summary>
    /// Liste der unterstützten Claims, die in ID Tokens enthalten sein können
    /// </summary>
    [JsonPropertyName("claims_supported")]
    public List<string>? ClaimsSupported { get; set; }

    /// <summary>
    /// Liste der unterstützten PKCE Code Challenge Methods
    /// </summary>
    [JsonPropertyName("code_challenge_methods_supported")]
    public List<string>? CodeChallengeMethodsSupported { get; set; }

    /// <summary>
    /// Liste der unterstützten Token Endpoint Authentication Methods
    /// </summary>
    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public List<string>? TokenEndpointAuthMethodsSupported { get; set; }

    /// <summary>
    /// Liste der unterstützten Response Modes
    /// </summary>
    [JsonPropertyName("response_modes_supported")]
    public List<string>? ResponseModesSupported { get; set; }
}
