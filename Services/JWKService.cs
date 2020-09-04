using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using EaglesJungscharen.CT.IDP.Models;
using System.Linq;
using System.Collections.Generic;
using System;
namespace EaglesJungscharen.CT.IDP.Services {
    public class JWKService {

        
        public List<JsonWebKey> GetPublicKeys(FunctionContext<dynamic> fc) { 
            return null;

       }

       public JsonWebKey GetJWKFromPK(PublicKeyTE pke) {
           RSA rsa = RSA.Create();
           rsa.ImportRSAPublicKey(Convert.FromBase64String(pke.PublicKey), out _);
           RsaSecurityKey rsaSecurity = new RsaSecurityKey(rsa);
           rsaSecurity.KeyId = pke.RowKey;
           return JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaSecurity);
       }
    }
}