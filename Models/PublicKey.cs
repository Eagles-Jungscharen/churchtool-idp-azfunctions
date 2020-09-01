using Microsoft.Azure.Cosmos.Table;
using System;
namespace EaglesJungscharen.CT.IDP.Models {
    public class PublicKey:TableEntity {
        public string publicKey {set;get;}

        public void assignPublicKey(byte[] pkAsBytes) {
            this.publicKey = Convert.ToBase64String(pkAsBytes);
        }
    }
}