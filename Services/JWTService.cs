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
        Task<Tokens> BuildJWTToken(CTWhoami whoami, List<string> scopes, string extRef, string issuer, string audience, string? nonce = null);
        Task<bool> CheckRefreshToken(string refreshToken, string accessToken);
        Task<Tokens> CreateNewTokenFromAccessToken(string accessToken, string issuer);
        Task<Tokens?> UseRefreshTokenAsync(string refreshToken, string issuer, string audience);
    }

    public class JWTService(ExtendedAzureTableClientService tableClientService, ILogger<JWTService> logger) : IJWTService {

        public static readonly int Expires_In_AccessToken = 900; // 15 Minuten
        public static readonly int Expires_In_RefreshToken = 60 * 60 * 24 * 30; // 30 Tage
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
           await StorePublicKey(_keyId, rsa.ExportRSAPublicKey(), expiresIn);
           await StorePrivateKey(_keyId, rsa.ExportRSAPrivateKey(), expiresIn);
        }

        private async Task StorePublicKey(string keyId, byte[] pkAsBytes, DateTime expiresIn) {
            PublicKey pk = new()
            {
                KeyId = keyId,
                Expires = expiresIn,
                PublicKeyValue = Convert.ToBase64String(pkAsBytes)
            };
            await _publicKeyTableClient.InsertOrReplaceAsync(pk.KeyId, "ACCESS_PUBLIC", pk);
        }

        private async Task StorePrivateKey(string keyId, byte[] privateKeyAsBytes, DateTime expiresIn) {
            PrivateKey pk = new()
            {
                KeyId = keyId,
                Expires = expiresIn,
                PrivateKeyValue = Convert.ToBase64String(privateKeyAsBytes),
                PublicKeyId = keyId
            };
            await _privateKeyTableClient.InsertOrReplaceAsync( "LATEST","ACCESS_PRIVATE", pk);
        }

        public async Task<Tokens> BuildJWTToken(CTWhoami whoami, List<string> scopes, string extRef, string issuer, string audience, string? nonce = null) {
            await CheckKeys();
            string idToken = CreateIDToken(whoami, scopes, extRef, issuer, audience, nonce);
            string accessToken = CreateAccessToken(whoami, scopes, extRef, issuer, audience);
            string refreshToken = await CreateRefreshToken(accessToken);
            return Tokens.BuildTokens(idToken, accessToken, refreshToken, Expires_In_AccessToken, scopes);
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
                var response = await _privateKeyTableClient.GetByIdAsync( "LATEST", "ACCESS_PRIVATE");
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

        private string CreateIDToken(CTWhoami whoami, List<string> scopes, string extRef, string issuer, string audience, string? nonce) {
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
            var claims = BuildClaims(whoami, unixTimeSeconds.ToString(), scopes, extRef, nonce);
            var jwt = new JwtSecurityToken(
                audience: audience,
                issuer: issuer,
                claims: claims,
                notBefore: now,
                expires: now.AddSeconds(Expires_In_AccessToken),
                signingCredentials: signingCredentials
            );
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        private static Claim[] BuildClaims(CTWhoami whoami, string timeStamp, List<string> scopes, string extRef, string? nonce = null) {
            List<Claim> claims =
            [
                new Claim(JwtRegisteredClaimNames.Sub, whoami.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, timeStamp, ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Name, $"{whoami.FirstName} {whoami.LastName}".Trim()),
                new Claim(JwtRegisteredClaimNames.GivenName, whoami.FirstName ?? ""),
                new Claim(JwtRegisteredClaimNames.FamilyName, whoami.LastName ?? ""),
                new Claim(JwtRegisteredClaimNames.Email, whoami.Email ?? ""),
                new Claim("st_ref", extRef),
            ];
            if (!string.IsNullOrEmpty(nonce)) {
                claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));
            }
            if (scopes.Count > 0) {
                claims.AddRange(scopes.Select(val => new Claim("scopes", val)));
            }
            return [.. claims];
        }

        private string CreateAccessToken(CTWhoami whoami, List<string> scopes, string extRef, string issuer, string audience) {
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
                audience: audience,
                issuer: issuer,
                claims: claims,
                notBefore: now,
                expires: now.AddSeconds(Expires_In_AccessToken),
                signingCredentials: signingCredentials
            );
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        private async Task<string> CreateRefreshToken(string accessToken) {
            DateTime expiresIn = DateTime.UtcNow.AddSeconds(Expires_In_RefreshToken);
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
                if (token.Expires < DateTime.UtcNow) {
                    await _refreshTokenTableClient.DeleteEntityAsync(token.RefreshTokenValue, "REFRESH_TOKEN");
                    _logger.LogInformation("Refresh token expired: {RefreshToken}", refreshToken);
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

        public Task<Tokens> CreateNewTokenFromAccessToken(string accessToken, string issuer) {
            JwtSecurityTokenHandler jsth = new();
            JwtSecurityToken token = jsth.ReadJwtToken(accessToken);
            CTWhoami cTWhoami = new()
            {
                Id = int.TryParse(token.Claims.FirstOrDefault(claim => claim.Type == JwtRegisteredClaimNames.Sub)?.Value, out var id) ? id : 0,
                FirstName = token.Claims.FirstOrDefault(claim => claim.Type == "given_name")?.Value,
                LastName = token.Claims.FirstOrDefault(claim => claim.Type == "family_name")?.Value,
                Email = token.Claims.FirstOrDefault(claim => claim.Type == "email")?.Value
            };
            var extRef = token.Claims.First(claim => claim.Type == "st_ref").Value;
            var audience = token.Audiences.FirstOrDefault() ?? "ct-auth";
            List<string> scopes = [.. token.Claims.Where(claim => claim.Type == "scopes").Select(fclaim => fclaim.Value)];
            return BuildJWTToken(cTWhoami, scopes, extRef, issuer, audience);
        }

        public async Task<Tokens?> UseRefreshTokenAsync(string refreshToken, string issuer, string audience) {
            try {
                var response = await _refreshTokenTableClient.GetByIdAsync(refreshToken, "REFRESH_TOKEN");
                var storedToken = response?.Entity;
                if (storedToken == null) {
                    _logger.LogInformation("Refresh token not found: {RefreshToken}", refreshToken);
                    return null;
                }
                if (storedToken.Expires < DateTime.UtcNow) {
                    await _refreshTokenTableClient.DeleteEntityAsync(storedToken.RefreshTokenValue, "REFRESH_TOKEN");
                    _logger.LogInformation("Refresh token expired: {RefreshToken}", refreshToken);
                    return null;
                }
                await _refreshTokenTableClient.DeleteEntityAsync(storedToken.RefreshTokenValue, "REFRESH_TOKEN");
                _logger.LogInformation("Refresh token used and deleted: {RefreshToken}", refreshToken);
                return await CreateNewTokenFromAccessToken(storedToken.AccessToken, issuer);
            } catch (Azure.RequestFailedException ex) when (ex.Status == 404) {
                _logger.LogInformation("Refresh token not found: {RefreshToken}", refreshToken);
                return null;
            }
        }
    }
}