using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

using EaglesJungscharen.CT.IDP.Models.ChurchTools;
using EaglesJungscharen.CT.IDP.Models.Store;
using EaglesJungscharen.CT.IDP.Models;
using GuedesPlace.AzureTools.Tables;

namespace EaglesJungscharen.CT.IDP.Services {
    
    public interface IJWTService {
        Task<Tokens> BuildJWTToken(CTWhoami whoami, List<string> scopes, string extRef);
        Task<bool> CheckRefreshToken(string refreshToken, string accessToken);
        Task<Tokens> CreateNewTokenFromAccessToken(string accessToken);
    }

    public class JWTService(ExtendedAzureTableClientService tableClientService, ILogger<JWTService> logger) : IJWTService {

        public static readonly int Expires_In_AccessToken = 3600;
        public static readonly int Expires_In_PrivateKey = 43200;
        private readonly TypedAzureTableClient<PublicKey> _publicKeyTableClient =
        tableClientService.GetTypedTableClient<PublicKey>();
        private readonly TypedAzureTableClient<PrivateKey> _privateKeyTableClient =
        tableClientService.GetTypedTableClient<PrivateKey>();

        private readonly TypedAzureTableClient<RefreshToken> _refreshTokenTableClient =
        tableClientService.GetTypedTableClient<RefreshToken>();
        
        private readonly ILogger<JWTService> _logger = logger;
        private RSA? _privateRSAKey;
        private string? _keyId;


        public async Task CreateNewKey() {
           RSA rsa = RSA.Create();
           _privateRSAKey = rsa;
           _keyId = Guid.NewGuid().ToString();
           DateTime expiresIn = DateTime.UtcNow;
           expiresIn = expiresIn.AddSeconds(Expires_In_PrivateKey);
           await StorePublicKey(rsa.ExportRSAPublicKey(), expiresIn);
           await StorePrivateKey(rsa.ExportRSAPrivateKey(), expiresIn);
        }

        private async Task StorePublicKey(byte[] pkAsBytes, DateTime expiresIn) {
            PublicKey pk = new()
            {
                KeyId = _keyId!,
                Expires = expiresIn,
                PublicKeyValue = Convert.ToBase64String(pkAsBytes)
            };
            await _publicKeyTableClient.InsertOrReplaceAsync(pk.KeyId, "ACCESS_PUBLIC", pk);
        }

        private async Task StorePrivateKey(byte[] privateKeyAsBytes, DateTime expiresIn) {
            PrivateKey pk = new()
            {
                KeyId = _keyId!,
                Expires = expiresIn,
                PrivateKeyValue = Convert.ToBase64String(privateKeyAsBytes),
                PublicKeyId = _keyId!
            };
            await _privateKeyTableClient.InsertOrReplaceAsync( "LATEST","ACCESS_PRIVATE", pk);
        }

        public async Task<Tokens> BuildJWTToken(CTWhoami whoami, List<string> scopes, string extRef) {
            await CheckKeys();
            string idToken = CreateIDToken(whoami, scopes, extRef);
            string accessToken = CreateAccessToken(whoami, scopes, extRef);
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
                var response = await _privateKeyTableClient.GetByIdAsync("ACCESS_PRIVATE", "LATEST");
                var pke = response?.Entity;

                if(pke == null) {
                    _logger.LogInformation("No private key found.");
                    return false;
                }   
                
                _logger.LogInformation("Private Key found with PKID: {PublicKeyId}", pke.PublicKeyId);
                if (DateTime.Now < pke.Expires) {
                    _keyId = pke.PublicKeyId;
                    RSA rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(Convert.FromBase64String(pke.PrivateKeyValue), out _);
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

        private string CreateIDToken(CTWhoami whoami, List<string> scopes, string extRef) {
            RsaSecurityKey rsaKey = new(_privateRSAKey)
            {
                KeyId = _keyId
            };
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
            var now = DateTime.Now;
            var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();
            var claims = BuildClaims(whoami, unixTimeSeconds.ToString(), scopes, extRef);
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

        private static Claim[] BuildClaims(CTWhoami whoami, string timeStamp, List<string> scopes, string extRef) {
            List<Claim> claims =
            [
                new Claim(JwtRegisteredClaimNames.Sub, whoami.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, timeStamp, ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("firstname", whoami.FirstName ?? ""),
                new Claim("lastname", whoami.LastName ?? ""),
                new Claim("email", whoami.Email ?? ""),
                new Claim("st_ref", extRef),
            ];
            if (scopes.Count > 0) {
                claims.AddRange(scopes.Select(val => new Claim("scopes", val)));
            }
            return [.. claims];
        }

        private string CreateAccessToken(CTWhoami whoami, List<string> scopes, string extRef) {
            RsaSecurityKey rsaKey = new(_privateRSAKey)
            {
                KeyId = _keyId
            };
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
            var now = DateTime.Now;
            var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();
            var claims = BuildClaims(whoami, unixTimeSeconds.ToString(), scopes, extRef);
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
            DateTime expiresIn = DateTime.UtcNow.AddSeconds(Expires_In_AccessToken);
            string refreshToken = Guid.NewGuid().ToString();
            RefreshToken rtTE = new()
            {
                AccessToken = accessToken,
                Expires = expiresIn,
                RefreshTokenValue = refreshToken
            };
            await _refreshTokenTableClient.InsertOrReplaceAsync(refreshToken, "REFRESH_TOKEN", rtTE);
            return refreshToken;
        }

        public async Task<bool> CheckRefreshToken(string refreshToken, string accessToken) {
            try {
                var response = await _refreshTokenTableClient.GetByIdAsync(refreshToken, "REFRESH_TOKEN");
                RefreshToken? token = response?.Entity;
                if (token == null) {
                    _logger.LogInformation("Refresh token not found: {RefreshToken}", refreshToken);
                    return false;
                }

                if (token.AccessToken == accessToken) {
                    await _refreshTokenTableClient.DeleteEntityAsync(token.RefreshTokenValue, "REFRESH_TOKEN");
                    return true;
                }
                return false;
            } catch (Azure.RequestFailedException ex) when (ex.Status == 404) {
                _logger.LogInformation("Refresh token not found: {RefreshToken}", refreshToken);
                return false;
            }
        }

        public Task<Tokens> CreateNewTokenFromAccessToken(string accessToken) {
            JwtSecurityTokenHandler jsth = new();
            JwtSecurityToken token = jsth.ReadJwtToken(accessToken);
            CTWhoami cTWhoami = new()
            {
                FirstName = token.Claims.First(claim => claim.Type == "firstname").Value,
                LastName = token.Claims.First(claim => claim.Type == "lastname").Value,
                Email = token.Claims.First(claim => claim.Type == "email").Value
            };
            var extRef = token.Claims.First(claim => claim.Type == "st_ref").Value;
            List<string> scopes = token.Claims.Where(claim => claim.Type == "scopes").Select(fclaim => fclaim.Value).ToList();
            return BuildJWTToken(cTWhoami, scopes, extRef);
        }
    }
}