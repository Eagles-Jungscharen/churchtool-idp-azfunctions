using Microsoft.Azure.Cosmos.Table;
using System.Security.Cryptography;
using System;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

using EaglesJungscharen.CT.IDP.Models;

namespace EaglesJungscharen.CT.IDP.Services {
    public class JWTService {

        public static int Expires_In_AccessToken = 3600;
        public static int Expires_In_PrivateKey = 43200;
        private RSA privateRSAKey;
        private string keyId;
        public JWTService() {
        }

        public async Task CreateNewKey(FunctionContext<dynamic> fc) {
           RSA rsa = RSA.Create();
           this.privateRSAKey = rsa;
           this.keyId = Guid.NewGuid().ToString();
           DateTime expiresIn = DateTime.Now;
           expiresIn = expiresIn.AddSeconds(JWTService.Expires_In_PrivateKey);
           await storePublicKey(fc,rsa.ExportRSAPublicKey(), expiresIn);
           await storePrivateKey(fc, rsa.ExportRSAPrivateKey(), expiresIn);
        }

        private async Task storePublicKey(FunctionContext<dynamic> fc, byte[] pkAsBytes, DateTime expiresIn) {
            PublicKeyTE pk = new PublicKeyTE();
            pk.PartitionKey = "ACCESS_PK";
            pk.RowKey = this.keyId;
            pk.Expires = expiresIn;
            pk.AssignPublicKey(pkAsBytes);
            TableOperation insertOrMerge = TableOperation.InsertOrMerge(pk);
            await fc.Table.ExecuteAsync(insertOrMerge);
        }

        private async Task storePrivateKey(FunctionContext<dynamic> fc, byte[] privateKeyAsBytes, DateTime expiresIn) {
            PrivateKeyTE pk = new PrivateKeyTE();
            pk.PartitionKey = "ACCESS_PRIVATE";
            pk.RowKey = "LATEST";
            pk.PublicKeyId = this.keyId;
            pk.Expires = expiresIn;
            pk.AssignePrivateKey(privateKeyAsBytes);
            TableOperation insertOrMerge = TableOperation.InsertOrReplace(pk);
            await fc.Table.ExecuteAsync(insertOrMerge);
        }
        public async Task<Tokens> BuildJWTToken(CTWhoami whoami, FunctionContext<dynamic> fc) {
            await checkKeys(fc);
            string idToken = createIDToken(whoami, fc);
            string accessToken = createAccessToken(whoami, fc);
            string refreshToken = createRefreshToken(fc, accessToken);
            return Tokens.BuildTokens(idToken, accessToken, refreshToken, JWTService.Expires_In_AccessToken);
        }

        private async Task checkKeys(FunctionContext<dynamic> fc){
            if (this.privateRSAKey == null){
                if (!await this.loadKeys(fc)) {
                    await this.CreateNewKey(fc);
                }
            } 
        }


        private async Task<bool> loadKeys(FunctionContext<dynamic> fc) {
            fc.Log.LogInformation("Loading Keys");
            TableOperation getLatestKey = TableOperation.Retrieve<PrivateKeyTE>("ACCESS_PRIVATE", "LATEST");
            TableResult result = await fc.Table.ExecuteAsync(getLatestKey);
            PrivateKeyTE pke = result.Result as PrivateKeyTE;
            if (pke == null) {
                fc.Log.LogInformation("No private key found.");
                return false;
            } else {
                fc.Log.LogInformation("Private Key found with PKID: {PublicKeyId}", pke.PublicKeyId);
                if (pke.Expires != null && DateTime.Now < pke.Expires) {
                    this.keyId = pke.PublicKeyId;
                    RSA rsa = RSA.Create();
                    rsa.ImportRSAPrivateKey(Convert.FromBase64String(pke.PrivateKey), out _);
                    this.privateRSAKey = rsa;
                    return true;
                } else {
                    fc.Log.LogInformation("Private Key is expired!");
                    return false;
                }
            }
        }

        private string createIDToken(CTWhoami whoami, FunctionContext<dynamic> fc) {
            RsaSecurityKey rsaKey = new RsaSecurityKey(this.privateRSAKey);
            rsaKey.KeyId = this.keyId;
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
            var now = DateTime.Now;
            var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();

            var jwt = new JwtSecurityToken(
                audience: "ct.auth",
                issuer: "CT_IDP",
                claims: new Claim[] {
                    new Claim(JwtRegisteredClaimNames.Iat, unixTimeSeconds.ToString(), ClaimValueTypes.Integer64),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("firstname", whoami.firstName),
                    new Claim("lastname", whoami.lastName),
                    new Claim("email", whoami.email)
                },
                notBefore: now,
                expires: now.AddSeconds(JWTService.Expires_In_AccessToken),
                signingCredentials: signingCredentials
            );
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        private string createAccessToken(CTWhoami whoami, FunctionContext<dynamic> fc) {
            RsaSecurityKey rsaKey = new RsaSecurityKey(this.privateRSAKey);
            rsaKey.KeyId = this.keyId;
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
            var now = DateTime.Now;
            var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();

            var jwt = new JwtSecurityToken(
                audience: "ct.test.",
                issuer: "CT_IDP",
                claims: new Claim[] {
                    new Claim(JwtRegisteredClaimNames.Iat, unixTimeSeconds.ToString(), ClaimValueTypes.Integer64),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim("firstname", whoami.firstName),
                    new Claim("lastname", whoami.lastName),
                    new Claim("email", whoami.email)
                },
                notBefore: now,
                expires: now.AddSeconds(JWTService.Expires_In_AccessToken),
                signingCredentials: signingCredentials
            );
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }
        private string createRefreshToken(FunctionContext<dynamic> fc, string accessToken) {
            DateTime expiresIn = DateTime.Now;
            expiresIn.AddSeconds(JWTService.Expires_In_AccessToken);
            string refreshToken = Guid.NewGuid().ToString();
            RefreshTokenTE rtTE = new RefreshTokenTE();
            rtTE.AccessToken = accessToken;
            rtTE.Expires = expiresIn;
            rtTE.RowKey = refreshToken;
            rtTE.PartitionKey = "REFRESH_TOKEN";
            TableOperation insertOrMerge = TableOperation.InsertOrMerge(rtTE);
            fc.Table.ExecuteAsync(insertOrMerge);
            return refreshToken;
        }
    }
}