using EaglesJungscharen.CT.IDP.Models.ChurchTools;
using EaglesJungscharen.CT.IDP.Models;
using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;

namespace EaglesJungscharen.CT.IDP.Services;

public interface ICTLoginService
{
    Task<LoginResult> DoLogin(string userName, string password);
    Task<CTWhoami?> GetWhoAmi(string loginToken, int id);
    Task<List<CTGroupContainer>> GetGroups(string loginToken, int id);
}

public class CTLoginService(HttpClient httpClient, ILogger<CTLoginService> logger) : ICTLoginService
{
    private readonly HttpClient _httpClient = httpClient;
    private readonly ILogger<CTLoginService> _logger = logger;
    private readonly string _cturl = Environment.GetEnvironmentVariable("CT_URL") ?? throw new InvalidOperationException("CT_URL not configured");

    public async Task<LoginResult> DoLogin(string userName, string password)
    {
        var payload = new { username = userName, password = password };
        var content = new StringContent(System.Text.Json.JsonSerializer.Serialize(payload), System.Text.Encoding.UTF8, "application/json");
        
        HttpResponseMessage response = await _httpClient.PostAsync($"{_cturl}/api/login/token", content);
        if (response.IsSuccessStatusCode)
        {
            var result = await response.Content.ReadFromJsonAsync<CTResponse<CTLoginTokenResponse>>();
            CTLoginTokenResponse? cTLoginResponse = result?.Data;
            return new LoginResult()
            {
                Error = false,
                CTLoginResponse = cTLoginResponse,
            };
        }
        else
        {
            return await BuildErrorResponse(response);
        }
    }

    private async Task<LoginResult> BuildErrorResponse(HttpResponseMessage response)
    {
        var errorPayload = await response.Content.ReadFromJsonAsync<CTErrorPayload>();
        _logger.LogError("Login failed with status code {StatusCode} and message {Message}", response.StatusCode, errorPayload?.Message);
        LoginResult lr = new()
        {
            Error = true,
            ErrorMessage = errorPayload?.TranslatedMessage ?? response.StatusCode.ToString()
        };
        return lr;
    }

    public async Task<CTWhoami?> GetWhoAmi(string loginToken, int id)
    {
        HttpRequestMessage request = new(HttpMethod.Get, _cturl + $"/api/persons/{id}");
        request.Headers.Add("Authorization", $"Login {loginToken}");
        HttpResponseMessage response = await _httpClient.SendAsync(request);
        var result = await response.Content.ReadFromJsonAsync<CTResponse<CTWhoami>>();
        return result?.Data ?? null;
    }

    public async Task<List<CTGroupContainer>> GetGroups(string loginToken, int id)
    {
        HttpRequestMessage request = new(HttpMethod.Get, $"{_cturl}/api/persons/{id}/groups");
        request.Headers.Add("Authorization", $"Login {loginToken}");
        HttpResponseMessage response = await _httpClient.SendAsync(request);
        var result = await response.Content.ReadFromJsonAsync<CTResponse<List<CTGroupContainer>>>();
        return result?.Data ?? [];
    }
}
