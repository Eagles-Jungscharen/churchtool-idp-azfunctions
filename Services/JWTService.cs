using System.Security.Cryptography;
using System;

namespace EaglesJungscharen.CT.IDP.Services {
    public class JWTService {

        private byte[] privateRSAKey;
        private string keyId;
        public JWTService() {
            this.CreateNewKey();
        }

        public void CreateNewKey() {
           RSA rsa = RSA.Create();
           this.privateRSAKey = rsa.ExportRSAPrivateKey();
           this.keyId = Guid.NewGuid().ToString();
 
        }
    }
}