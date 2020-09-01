using Microsoft.Azure.Cosmos.Table;
using System.Security.Cryptography;
using System;

using EaglesJungscharen.CT.IDP.Models;

namespace EaglesJungscharen.CT.IDP.Services {
    public class JWTService {

        private byte[] privateRSAKey;
        private string keyId;
        public JWTService() {
        }

        public void CreateNewKey(CloudTable cloudTable) {
           RSA rsa = RSA.Create();
           this.privateRSAKey = rsa.ExportRSAPrivateKey();
           this.keyId = Guid.NewGuid().ToString();
           storePublicKey(cloudTable,rsa.ExportRSAPublicKey());
        }

        private async void storePublicKey(CloudTable cloudTable, byte[] pkAsBytes) {
            PublicKey pk = new PublicKey();
            pk.PartitionKey = "ACCESS_PK";
            pk.RowKey = this.keyId;
            pk.assignPublicKey(pkAsBytes);
            TableOperation insertOrMerge = TableOperation.InsertOrMerge(pk);
            await cloudTable.ExecuteAsync(insertOrMerge);
        }
    }
}