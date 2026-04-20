using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using EaglesJungscharen.CT.IDP.Models;
using System.Linq;
using System.Collections.Generic;
using System;
using Azure.Data.Tables;

namespace EaglesJungscharen.CT.IDP.Services {
    
    public interface IJWKService {
        IEnumerable<JsonWebKey> GetPublicKeys();
    }

    public class JWKService : IJWKService {
        private readonly TableClient _tableClient;

        public JWKService(TableClient tableClient) {
            _tableClient = tableClient;
        }

        public IEnumerable<JsonWebKey> GetPublicKeys() {
            var allPK = _tableClient.Query<PublicKeyTE>(filter: $"PartitionKey eq 'ACCESS_PK'");
            return allPK.Select(pke => GetJWKFromPK(pke));
        }

        public JsonWebKey GetJWKFromPK(PublicKeyTE pke) {
            RSA rsa = RSA.Create();
            rsa.ImportRSAPublicKey(Convert.FromBase64String(pke.PublicKey!), out _);
            RsaSecurityKey rsaSecurity = new RsaSecurityKey(rsa);
            rsaSecurity.KeyId = pke.RowKey;

            return JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaSecurity);
        }
    }
}