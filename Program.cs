using Azure.Data.Tables;
using EaglesJungscharen.CT.IDP.Models.Store;
using EaglesJungscharen.CT.IDP.Services;
using GuedesPlace.AzureTools.Tables;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = FunctionsApplication.CreateBuilder(args);

builder.ConfigureFunctionsWebApplication();

// Register TableServiceClient
var storageConnectionString = Environment.GetEnvironmentVariable("AzureWebJobsStorage");
var tableClientService = new ExtendedAzureTableClientService(storageConnectionString!);
var publicKeyTableClient = tableClientService.CreateAndRegisterTableClient<PublicKey>("PublicKeyTable");
var privateKeyTableClient = tableClientService.CreateAndRegisterTableClient<PrivateKey>("PrivateKeyTable");
var refreshTokenTableClient = tableClientService.CreateAndRegisterTableClient<RefreshToken>("RefreshTokenTable");
var userTokenTableClient = tableClientService.CreateAndRegisterTableClient<UserLoginTokens>("UserLoginTokensTable");

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
builder.Services.AddSingleton<UserTokenService>();

builder.Build().Run();
