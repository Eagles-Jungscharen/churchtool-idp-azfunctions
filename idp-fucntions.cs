using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.Cosmos.Table;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System.Net.Http;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Services;

namespace EaglesJungscharen.CT.IDP.Functions
{

    public static class Authenticate
    {
        static readonly HttpClient httpClient = new HttpClient(new HttpClientHandler(){UseCookies=false});
        static readonly JWTService jwtService = new JWTService();
        [FunctionName("authenticate")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req, [Table("PublicKeys")] CloudTable cloudTable,
            ILogger log)
        {
            log.LogInformation("Login requestes");
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            if (data == null) {
                return new BadRequestObjectResult("No Payload available");
            }
            string username = data.username;
            string password = data.password;
            if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password)) {
                return new BadRequestObjectResult("Nix username or password");
            }
            string ctURL = System.Environment.GetEnvironmentVariable("CT_URL");
            CTLoginService service = new CTLoginService(ctURL);
            LoginResult lr =  await service.DoLogin(username,password,httpClient);
            if (!lr.Error) {
                CTWhoami cTWhoami = await service.GetWhoAmi(lr.SetCookieHeader,httpClient);
                return new OkObjectResult(cTWhoami);
            }
            return new UnauthorizedResult();
        }
    }
}
