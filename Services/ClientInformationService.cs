using GuedesPlace.AzureTools.Tables;
using EaglesJungscharen.CT.IDP.Models.Store;

namespace EaglesJungscharen.CT.IDP.Services;

public record ValidationResult(bool IsValid, IReadOnlyList<string> Errors);

public interface IClientInformationService
{
    Task<ClientInformation?> GetClientInformationByIdAsync(string clientId);
    ValidationResult ValidateEntry(ClientInformation entry);
}

public class ClientInformationService(ExtendedAzureTableClientService tableClientService) : IClientInformationService
{
    private readonly TypedAzureTableClient<ClientInformation> _clientInformationTableClient =
        tableClientService.GetTypedTableClient<ClientInformation>();

    public async Task<ClientInformation?> GetClientInformationByIdAsync(string clientId)
    {
        var result = await _clientInformationTableClient.GetByIdAsync(clientId, "CLIENT_INFO");
        return result?.Entity;
    }

    public ValidationResult ValidateEntry(ClientInformation entry)
    {
        var errors = new List<string>();

        foreach (var uri in entry.RedirectUris)
        {
            if (!uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase) &&
                !uri.StartsWith("http://localhost/", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add($"Ungültige Redirect-URI '{uri}': muss mit 'https://' oder 'http://localhost/' beginnen");
            }
        }

        return new ValidationResult(errors.Count == 0, errors);
    }
}
