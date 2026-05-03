using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Azure.Functions.Worker.Middleware;
using System.Net;

namespace EaglesJungscharen.CT.IDP.Middleware;

/// <summary>
/// CORS Middleware für Azure Functions (.NET Isolated)
/// Fügt CORS-Header zu allen HTTP-Responses hinzu und behandelt OPTIONS-Preflight-Requests
/// </summary>
public class CorsMiddleware : IFunctionsWorkerMiddleware
{
    public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
    {
        var requestData = await context.GetHttpRequestDataAsync();
        
        if (requestData != null)
        {
            // OPTIONS Preflight-Request abfangen
            if (requestData.Method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
            {
                var preflightResponse = requestData.CreateResponse(HttpStatusCode.OK);
                AddCorsHeaders(preflightResponse, requestData);
                
                context.GetInvocationResult().Value = preflightResponse;
                return;
            }
        }

        // Normale Request-Verarbeitung
        await next(context);

        // CORS-Header zur Response hinzufügen
        if (requestData != null)
        {
            var invocationResult = context.GetInvocationResult();
            if (invocationResult?.Value is HttpResponseData response)
            {
                AddCorsHeaders(response, requestData);
            }
        }
    }

    private static void AddCorsHeaders(HttpResponseData response, HttpRequestData request)
    {
        // Origin Header aus Request lesen, falls vorhanden
        string origin = request.Headers.TryGetValues("Origin", out var origins) 
            ? origins.FirstOrDefault() ?? "*" 
            : "*";

        response.Headers.Add("Access-Control-Allow-Origin", origin);
        response.Headers.Add("Access-Control-Allow-Credentials", "true");
        response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization, x-functions-key");
        response.Headers.Add("Access-Control-Expose-Headers", "location");
        response.Headers.Add("Access-Control-Max-Age", "86400");
    }
}
