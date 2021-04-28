using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using EaglesJungscharen.CT.IDP.Models;
using System.Linq;
using System.Collections.Generic;
using System;
using Microsoft.Azure.Cosmos.Table;
using Microsoft.Azure.Cosmos.Table.Queryable;
using Microsoft.Extensions.Logging;


namespace EaglesJungscharen.CT.IDP.Services {
    public class JWKService {

        
        public IEnumerable<JsonWebKey> GetPublicKeys(FunctionContext<dynamic> fc) {
            
            string filter = TableQuery.GenerateFilterCondition("PartitionKey", QueryComparisons.Equal, "ACCESS_PK");
            TableQuery<PublicKeyTE> employeeQuery = new TableQuery<PublicKeyTE>().Where(filter);
            IEnumerable<PublicKeyTE> allPK = fc.Table.ExecuteQuery(employeeQuery);
            return allPK.Select(pke=> {
                JsonWebKey jwk = this.GetJWKFromPK(pke);
                return jwk;
            });

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