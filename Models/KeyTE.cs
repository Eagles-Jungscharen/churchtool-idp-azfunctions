using Microsoft.Azure.Cosmos.Table;
using System;
namespace EaglesJungscharen.CT.IDP.Models {
    public class PublicKeyTE:TableEntity {
        public string PublicKey {set;get;}

        public DateTime Expires {set;get;}

        public void AssignPublicKey(byte[] pkAsBytes) {
            this.PublicKey = Convert.ToBase64String(pkAsBytes);
        }
    }

    public class PrivateKeyTE:TableEntity {
        public string PrivateKey {set;get;}

        public string PublicKeyId {set;get;}

        public DateTime Expires {set;get;}

        public void AssignePrivateKey(byte[] pkAsBytes) {
            this.PrivateKey = Convert.ToBase64String(pkAsBytes);
        }
    }

    public class RefreshTokenTE:TableEntity {
        public string AccessToken {set;get;}

        public DateTime Expires {set;get;}
    }
}