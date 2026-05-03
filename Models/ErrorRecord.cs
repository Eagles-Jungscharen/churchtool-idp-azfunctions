using System.Text.Json.Serialization;

namespace EaglesJungscharen.CT.IDP.Models;

/// <summary>
/// Standardisierte Fehlerantwort für BadRequest-Responses.
/// JSON-Serialisierung in camelCase für REST-API-Konventionen.
/// </summary>
public class ErrorRecord
{
    /// <summary>
    /// Menschenlesbare Fehlermeldung auf Deutsch.
    /// </summary>
    [JsonPropertyName("error")]
    public required string Error { get; init; }

    /// <summary>
    /// Eindeutige Fehlernummer zur maschinenlesbaren Identifikation.
    /// Gruppierung: 1000er (Authorize), 2000er (Authenticate), 3000er (Token), 4000er (RefreshToken), 5000er (Login).
    /// </summary>
    [JsonPropertyName("errorNumber")]
    public required int ErrorNumber { get; init; }
}
