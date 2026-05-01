using GuedesPlace.AzureTools.Tables;
using EaglesJungscharen.CT.IDP.Models.Store;

namespace EaglesJungscharen.CT.IDP.Services;

public record ValidationResult(bool IsValid, IReadOnlyList<string> Errors);

public interface IClientInformationService
{
    Task<ClientInformation?> GetClientInformationByIdAsync(string clientId);
    Task<ClientInformation> CreateClientInformationAsync(ClientInformation clientInfo);
    Task<ClientInformation?> UpdateClientInformationAsync(string clientId, string? name, string? owner, List<string>? redirectUris);
    Task<bool> DeleteClientInformationAsync(string clientId);
    Task<IEnumerable<ClientInformation>> GetAllClientInformationsAsync();
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

    public async Task<ClientInformation> CreateClientInformationAsync(ClientInformation clientInfo)
    {
        await _clientInformationTableClient.InsertOrReplaceAsync(clientInfo.ClientId, "CLIENT_INFO", clientInfo);
        return clientInfo;
    }

    public async Task<ClientInformation?> UpdateClientInformationAsync(string clientId, string? name, string? owner, List<string>? redirectUris)
    {
        var existing = await GetClientInformationByIdAsync(clientId);
        if (existing == null)
        {
            return null;
        }

        // Partielle Aktualisierung - nur die angegebenen Felder überschreiben
        if (name != null)
        {
            existing.Name = name;
        }
        if (owner != null)
        {
            existing.Owner = owner;
        }
        if (redirectUris != null)
        {
            existing.RedirectUris = redirectUris;
        }

        await _clientInformationTableClient.InsertOrReplaceAsync(clientId, "CLIENT_INFO", existing);
        return existing;
    }

    public async Task<bool> DeleteClientInformationAsync(string clientId)
    {
        var existing = await GetClientInformationByIdAsync(clientId);
        if (existing == null)
        {
            return false;
        }

        await _clientInformationTableClient.DeleteEntityAsync(clientId, "CLIENT_INFO");
        return true;
    }

    public async Task<IEnumerable<ClientInformation>> GetAllClientInformationsAsync()
    {
        var result = await _clientInformationTableClient.GetAllAsync("CLIENT_INFO");
        return result.Select(r => r.Entity);
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
