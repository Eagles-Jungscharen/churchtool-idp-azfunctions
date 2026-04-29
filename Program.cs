using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Models.Store;
using EaglesJungscharen.CT.IDP.Services;
using GuedesPlace.AzureTools.Configuration.Extensions;
using GuedesPlace.AzureTools.Tables;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = FunctionsApplication.CreateBuilder(args);

builder.ConfigureFunctionsWebApplication();

var configuration = builder.Configuration;
configuration.CheckConfigurationValuesAvailable(["AzureWebJobsStorage", "CT_URL", "LOGIN_CLIENT_URL"]);
var storageConnectionString = configuration["AzureWebJobsStorage"]!;
var churchToolsURL = configuration["CT_URL"]!;
var loginClientURL = configuration["LOGIN_CLIENT_URL"]!;

builder.Services.AddOptions<ServiceConfiguration>().Configure(s =>
{
    s.ChurchToolsURL = churchToolsURL;
    s.LoginClientURL = loginClientURL;
});

// Register TableServiceClient
var tableClientService = new ExtendedAzureTableClientService(storageConnectionString!);
var publicKeyTableClient = tableClientService.CreateAndRegisterTableClient<PublicKey>("PublicKeyTable");
var privateKeyTableClient = tableClientService.CreateAndRegisterTableClient<PrivateKey>("PrivateKeyTable");
var refreshTokenTableClient = tableClientService.CreateAndRegisterTableClient<RefreshToken>("RefreshTokenTable");
var userTokenTableClient = tableClientService.CreateAndRegisterTableClient<UserLoginTokens>("UserLoginTokensTable");
var authorizationRequestTableClient = tableClientService.CreateAndRegisterTableClient<AuthorizationRequest>("AuthorizationRequestTable");
var authorizationCodeTableClient = tableClientService.CreateAndRegisterTableClient<AuthorizationCode>("AuthorizationCodeTable");
var clientInformationTableClient = tableClientService.CreateAndRegisterTableClient<ClientInformation>("ClientInformationTable");

builder.Services.AddSingleton(tableClientService);

// Register HttpClient with IHttpClientFactory
builder.Services.AddHttpClient<ICTLoginService, CTLoginService>(client =>
{
    client.DefaultRequestHeaders.Add("User-Agent", "CT-IDP-AzFunctions");
}).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    UseCookies = false
});

// Register services
builder.Services.AddSingleton<IJWTService, JWTService>();
builder.Services.AddSingleton<IJWKService, JWKService>();
builder.Services.AddSingleton<IClientInformationService, ClientInformationService>();
builder.Services.AddSingleton<IAuthorizationRequestService, AuthorizationRequestService>();
builder.Services.AddSingleton<IAuthorizationCodeService, AuthorizationCodeService>();
builder.Services.AddSingleton<UserTokenService>();

builder.Build().Run();
