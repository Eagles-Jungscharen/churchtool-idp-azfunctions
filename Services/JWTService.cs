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

        private RSA privateRSAKey;
        private string keyId;
        public JWTService() {
        }

        public async Task CreateNewKey(FunctionContext<dynamic> fc) {
           RSA rsa = RSA.Create();
           this.privateRSAKey = rsa;
           this.keyId = Guid.NewGuid().ToString();
           await storePublicKey(fc,rsa.ExportRSAPublicKey());
           await storePrivateKey(fc, rsa.ExportRSAPrivateKey(), rsa.ExportRSAPublicKey());
        }

        private async Task storePublicKey(FunctionContext<dynamic> fc, byte[] pkAsBytes) {
            PublicKeyTE pk = new PublicKeyTE();
            pk.PartitionKey = "ACCESS_PK";
            pk.RowKey = this.keyId;
            pk.AssignPublicKey(pkAsBytes);
            TableOperation insertOrMerge = TableOperation.InsertOrMerge(pk);
            await fc.Table.ExecuteAsync(insertOrMerge);
        }

        private async Task storePrivateKey(FunctionContext<dynamic> fc, byte[] privateKeyAsBytes, byte [] publicKeyAsBytes) {
            PrivateKeyTE pk = new PrivateKeyTE();
            pk.PartitionKey = "ACCESS_PRIVATE";
            pk.RowKey = "LATEST";
            pk.PublicKeyId = this.keyId;
            pk.AssignePrivateKey(privateKeyAsBytes);
            pk.AssignePublicKey(publicKeyAsBytes);
            TableOperation insertOrMerge = TableOperation.InsertOrMerge(pk);
            await fc.Table.ExecuteAsync(insertOrMerge);

        }
        public async Task<Tokens> BuildJWTToken(CTWhoami whoami, FunctionContext<dynamic> fc) {
            await checkKeys(fc);
            string idToken = createIDToken(whoami, fc);
            string accessToken = createAccessToken(whoami, fc);
            string refreshToken = createRefreshToken(fc);
            return Tokens.BuildTokens(idToken, accessToken, refreshToken);
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
            }
            fc.Log.LogInformation("Private Key found: ", pke);
            this.keyId = pke.PublicKeyId;
            RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(Convert.FromBase64String(pke.PrivateKey), out _);
            this.privateRSAKey = rsa;
            return true;
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
                expires: now.AddMinutes(30),
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
                expires: now.AddMinutes(30),
                signingCredentials: signingCredentials
            );
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }
    private string createRefreshToken(FunctionContext<dynamic> fc) {
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
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                },
                notBefore: now,
                expires: now.AddMinutes(30),
                signingCredentials: signingCredentials
            );
            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }
    }
}