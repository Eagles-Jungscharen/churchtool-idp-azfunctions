using EaglesJungscharen.CT.IDP.Models.ChurchTools;
using EaglesJungscharen.CT.IDP.Models;
using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Logging;

namespace EaglesJungscharen.CT.IDP.Services;

public interface ICTLoginService
{
    Task<LoginResult> DoLogin(string userName, string password);
    Task<CTWhoami?> GetWhoAmi(string setCookieHeader);
    Task<List<CTGroupContainer>> GetGroups(string setCookieHeader, int id);
}

public class CTLoginService(HttpClient httpClient, ILogger<CTLoginService> logger) : ICTLoginService
{
    private readonly HttpClient _httpClient = httpClient;
    private readonly ILogger<CTLoginService> _logger = logger;
    private readonly string _cturl = Environment.GetEnvironmentVariable("CT_URL") ?? throw new InvalidOperationException("CT_URL not configured");

    public async Task<LoginResult> DoLogin(string userName, string password)
    {
        List<KeyValuePair<string, string>> parameters =
        [
            new KeyValuePair<string, string>("username", userName),
            new KeyValuePair<string, string>("password", password),
        ];
        HttpContent content = new FormUrlEncodedContent(parameters);

        HttpResponseMessage response = await _httpClient.PostAsync($"{_cturl}/api/login", content);
        if (response.IsSuccessStatusCode)
        {
            var result = await response.Content.ReadFromJsonAsync<CTResponse<CTLoginResponse>>();
            CTLoginResponse? cTLoginResponse = result?.Data;
            string cookieHeaders = "";
            if (response.Headers.TryGetValues("Set-Cookie", out IEnumerable<string>? cookHeaderValues))
            {
                cookieHeaders = cookHeaderValues.First();
            }
            return new LoginResult()
            {
                Error = false,
                CTLoginResponse = cTLoginResponse,
                SetCookieHeader = cookieHeaders
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

    public async Task<CTWhoami?> GetWhoAmi(string setCookieHeader)
    {
        HttpRequestMessage request = new(HttpMethod.Get, _cturl + "/api/whoami?only_allow_authenticated=true");
        CookieContainer container = new();
        Uri ctUri = new(_cturl);
        container.SetCookies(ctUri, setCookieHeader);
        request.Headers.Add("Cookie", container.GetCookieHeader(ctUri));
        HttpResponseMessage response = await _httpClient.SendAsync(request);
        var result = await response.Content.ReadFromJsonAsync<CTResponse<CTWhoami>>();
        return result?.Data ?? null;
    }

    public async Task<List<CTGroupContainer>> GetGroups(string setCookieHeader, int id)
    {
        HttpRequestMessage request = new(HttpMethod.Get, $"{_cturl}/api/persons/{id}/groups");
        CookieContainer container = new();
        Uri ctUri = new(_cturl);
        container.SetCookies(ctUri, setCookieHeader);
        request.Headers.Add("Cookie", container.GetCookieHeader(ctUri));
        HttpResponseMessage response = await _httpClient.SendAsync(request);
        var result = await response.Content.ReadFromJsonAsync<CTResponse<List<CTGroupContainer>>>();
        return result?.Data ?? [];
    }
}
