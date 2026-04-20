using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using EaglesJungscharen.CT.IDP.Models;
using EaglesJungscharen.CT.IDP.Services;
using System.Linq;
using System.Collections.Generic;
using Microsoft.Azure.Functions.Worker;

namespace EaglesJungscharen.CT.IDP.Functions
{
    public class Authenticate
    {
        private readonly ICTLoginService _loginService;
        private readonly IJWTService _jwtService;
        private readonly ILogger<Authenticate> _logger;

        public Authenticate(ICTLoginService loginService, IJWTService jwtService, ILogger<Authenticate> logger)
        {
            _loginService = loginService;
            _jwtService = jwtService;
            _logger = logger;
        }

        [Function("authenticate")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req)
        {
            _logger.LogInformation("Login requested");
            
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic? data = JsonConvert.DeserializeObject(requestBody);
            if (data == null)
            {
                return new BadRequestObjectResult("No Payload available");
            }

            string? username = data.username;
            string? password = data.password;
            if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                return new BadRequestObjectResult("Nix username or password");
            }

            LoginResult lr = await _loginService.DoLogin(username, password);
            _logger.LogInformation("Result: {Error}", lr.Error);
            
            if (!lr.Error)
            {
                CTWhoami cTWhoami = await _loginService.GetWhoAmi(lr.SetCookieHeader!);
                List<CTGroupContainer> groups = await _loginService.GetGroups(lr.SetCookieHeader!, cTWhoami.id);
                List<string> scopes = groups.Select(gc => "ct_group_" + gc.group?.domainIdentifier).ToList();
                Tokens tokens = await _jwtService.BuildJWTToken(cTWhoami, scopes);
                return new OkObjectResult(tokens);
            }
            return new UnauthorizedResult();
        }
    }

    public class GetPublicKeys
    {
        private readonly IJWKService _jwkService;

        public GetPublicKeys(IJWKService jwkService)
        {
            _jwkService = jwkService;
        }

        [Function("well-known")]
        public IActionResult Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", "get", Route = "jwks.json")] HttpRequest req)
        {
            var jwkKeys = _jwkService.GetPublicKeys();
            return new JsonResult(new { keys = jwkKeys }, new JsonSerializerSettings()
            {
                NullValueHandling = NullValueHandling.Ignore
            });
        }
    }

    public class RefreshToken
    {
        private readonly IJWTService _jwtService;
        private readonly ILogger<RefreshToken> _logger;

        public RefreshToken(IJWTService jwtService, ILogger<RefreshToken> logger)
        {
            _jwtService = jwtService;
            _logger = logger;
        }

        [Function("refresh")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req)
        {
            _logger.LogInformation("Refresh requested");
            
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            string? accessToken = req.Headers.FirstOrDefault(header => header.Key == "Authorization").Value;
            
            if (accessToken == null || !accessToken.StartsWith("Bearer"))
            {
                return new UnauthorizedResult();
            }
            
            dynamic? data = JsonConvert.DeserializeObject(requestBody);
            if (data == null)
            {
                return new BadRequestObjectResult("No Payload available");
            }
            if (data.refreshToken == null)
            {
                return new BadRequestObjectResult("No refreshToken submitted");
            }
            
            string refreshToken = data.refreshToken;
            string accessTokenShort = accessToken.Substring(7);
            _logger.LogInformation("Access token: {AccessToken}", accessTokenShort);
            
            if (_jwtService.CheckRefreshToken(refreshToken, accessTokenShort))
            {
                Tokens tokens = await _jwtService.CreateNewTokenFromAccessToken(accessTokenShort);
                return new OkObjectResult(tokens);
            }
            return new BadRequestObjectResult("Refresh and access Token Combination not valid");
        }
    }
}
