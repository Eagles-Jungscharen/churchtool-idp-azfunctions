using Azure.Data.Tables;
using System.Security.Cryptography;
using System;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Collections.Generic;

using EaglesJungscharen.CT.IDP.Models;

namespace EaglesJungscharen.CT.IDP.Services {
    
    public interface IJWTService {
        Task<Tokens> BuildJWTToken(CTWhoami whoami, List<string> scopes);
        bool CheckRefreshToken(string refreshToken, string accessToken);
        Task<Tokens> CreateNewTokenFromAccessToken(string accessToken);
    }

    public class JWTService : IJWTService {

        public static int Expires_In_AccessToken = 3600;
        public static int Expires_In_PrivateKey = 43200;
        
        private readonly TableClient _tableClient;
        private readonly ILogger<JWTService> _logger;
        private RSA? _privateRSAKey;
        private string? _keyId;

        public JWTService(TableClient tableClient, ILogger<JWTService> logger) {
            _tableClient = tableClient;
            _logger = logger;
        }

        public async Task CreateNewKey() {
           RSA rsa = RSA.Create();
           _privateRSAKey = rsa;
           _keyId = Guid.NewGuid().ToString();
           DateTime expiresIn = DateTime.Now;
           expiresIn = expiresIn.AddSeconds(Expires_In_PrivateKey);
           await StorePublicKey(rsa.ExportRSAPublicKey(), expiresIn);
           await StorePrivateKey(rsa.ExportRSAPrivateKey(), expiresIn);
        }

        private async Task StorePublicKey(byte[] pkAsBytes, DateTime expiresIn) {
            PublicKeyTE pk = new PublicKeyTE();
            pk.PartitionKey = "ACCESS_PK";
            pk.RowKey = _keyId!;
            pk.Expires = expiresIn;
            pk.AssignPublicKey(pkAsBytes);
            await _tableClient.UpsertEntityAsync(pk);
        }

        private async Task StorePrivateKey(byte[] privateKeyAsBytes, DateTime expiresIn) {
            PrivateKeyTE pk = new PrivateKeyTE();
            pk.PartitionKey = "ACCESS_PRIVATE";
            pk.RowKey = "LATEST";
            pk.PublicKeyId = _keyId;
            pk.Expires = expiresIn;
            pk.AssignePrivateKey(privateKeyAsBytes);
            await _tableClient.UpsertEntityAsync(pk, TableUpdateMode.Replace);
        }

        public async Task<Tokens> BuildJWTToken(CTWhoami whoami, List<string> scopes) {
            await CheckKeys();
            string idToken = CreateIDToken(whoami, scopes);
            string accessToken = CreateAccessToken(whoami, scopes);
            string refreshToken = await CreateRefreshToken(accessToken);
            return Tokens.BuildTokens(idToken, accessToken, refreshToken, Expires_In_AccessToken);
        }

        private async Task CheckKeys() {
            if (_privateRSAKey == null) {
                if (!await LoadKeys()) {
                    await CreateNewKey();
                }
            }
        }

        private async Task<bool> LoadKeys() {
            _logger.LogInformation("Loading Keys");
            try {
                var response = await _tableClient.GetEntityAsync<PrivateKeyTE>("ACCESS_PRIVATE", "LATEST");
                PrivateKeyTE pke = response.Value;
                
                _logger.LogInformation("Private Key found with PKID: {PublicKeyId}", pke.PublicKeyId);
                if (DateTime.Now < pke.Expires) {
                    _keyId = pke.PublicKeyId;
                    RSA rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(Convert.FromBase64String(pke.PrivateKey!), out _);
                    _privateRSAKey = rsa;
                    return true;
                } else {
                    _logger.LogInformation("Private Key is expired!");
                    return false;
                }
            } catch (Azure.RequestFailedException ex) when (ex.Status == 404) {
                _logger.LogInformation("No private key found.");
                return false;
            }
        }

        private string CreateIDToken(CTWhoami whoami, List<string> scopes) {
            RsaSecurityKey rsaKey = new RsaSecurityKey(_privateRSAKey);
            rsaKey.KeyId = _keyId;
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
            var now = DateTime.Now;
            var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();
            var claims = BuildClaims(whoami, unixTimeSeconds.ToString(), scopes);
            var jwt = new JwtSecurityToken(
                audience: "ct.auth",
                issuer: "CT_IDP",
                claims: claims,
                notBefore: now,
                expires: now.AddSeconds(Expires_In_AccessToken),
                signingCredentials: signingCredentials
            );
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        private Claim[] BuildClaims(CTWhoami whoami, string timeStamp, List<string> scopes) {
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, timeStamp, ClaimValueTypes.Integer64));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim("firstname", whoami.firstName ?? ""));
            claims.Add(new Claim("lastname", whoami.lastName ?? ""));
            claims.Add(new Claim("email", whoami.email ?? ""));
            if (scopes.Count() > 0) {
                claims.AddRange(scopes.Select(val => new Claim("scopes", val)));
            }
            return claims.ToArray();
        }

        private string CreateAccessToken(CTWhoami whoami, List<string> scopes) {
            RsaSecurityKey rsaKey = new RsaSecurityKey(_privateRSAKey);
            rsaKey.KeyId = _keyId;
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
            var now = DateTime.Now;
            var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();
            var claims = BuildClaims(whoami, unixTimeSeconds.ToString(), scopes);
            var jwt = new JwtSecurityToken(
                audience: "ct.test.",
                issuer: "CT_IDP",
                claims: claims,
                notBefore: now,
                expires: now.AddSeconds(Expires_In_AccessToken),
                signingCredentials: signingCredentials
            );
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        private async Task<string> CreateRefreshToken(string accessToken) {
            DateTime expiresIn = DateTime.Now.AddSeconds(Expires_In_AccessToken);
            string refreshToken = Guid.NewGuid().ToString();
            RefreshTokenTE rtTE = new RefreshTokenTE();
            rtTE.AccessToken = accessToken;
            rtTE.Expires = expiresIn;
            rtTE.RowKey = refreshToken;
            rtTE.PartitionKey = "REFRESH_TOKEN";
            await _tableClient.UpsertEntityAsync(rtTE);
            return refreshToken;
        }

        public bool CheckRefreshToken(string refreshToken, string accessToken) {
            try {
                var response = _tableClient.GetEntity<RefreshTokenTE>("REFRESH_TOKEN", refreshToken);
                RefreshTokenTE token = response.Value;

                if (token.AccessToken?.Equals(accessToken) == true) {
                    _tableClient.DeleteEntity(token.PartitionKey, token.RowKey, token.ETag);
                    return true;
                }
                return false;
            } catch (Azure.RequestFailedException ex) when (ex.Status == 404) {
                _logger.LogInformation("Refresh token not found: {RefreshToken}", refreshToken);
                return false;
            }
        }

        public Task<Tokens> CreateNewTokenFromAccessToken(string accessToken) {
            JwtSecurityTokenHandler jsth = new JwtSecurityTokenHandler();
            JwtSecurityToken token = jsth.ReadJwtToken(accessToken);
            CTWhoami cTWhoami = new CTWhoami();
            cTWhoami.firstName = token.Claims.First(claim => claim.Type == "firstname").Value;
            cTWhoami.lastName = token.Claims.First(claim => claim.Type == "lastname").Value;
            cTWhoami.email = token.Claims.First(claim => claim.Type == "email").Value;
            List<string> scopes = token.Claims.Where(claim => claim.Type == "scopes").Select(fclaim => fclaim.Value).ToList();
            return BuildJWTToken(cTWhoami, scopes);
        }
    }
}