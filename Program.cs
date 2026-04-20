using Azure.Data.Tables;
using EaglesJungscharen.CT.IDP.Services;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = FunctionsApplication.CreateBuilder(args);

builder.ConfigureFunctionsWebApplication();

// Register TableServiceClient
var storageConnectionString = Environment.GetEnvironmentVariable("AzureWebJobsStorage");
builder.Services.AddSingleton(new TableServiceClient(storageConnectionString));
builder.Services.AddSingleton(sp =>
{
    var tableServiceClient = sp.GetRequiredService<TableServiceClient>();
    var tableClient = tableServiceClient.GetTableClient("PublicKeys");
    tableClient.CreateIfNotExists();
    return tableClient;
});

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

builder.Build().Run();
