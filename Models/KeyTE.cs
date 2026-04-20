using Azure;
using Azure.Data.Tables;
using System;

namespace EaglesJungscharen.CT.IDP.Models {
    public class PublicKeyTE : ITableEntity {
        public string PartitionKey { get; set; } = string.Empty;
        public string RowKey { get; set; } = string.Empty;
        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }

        public string? PublicKey { get; set; }
        public DateTime Expires { get; set; }

        public void AssignPublicKey(byte[] pkAsBytes) {
            this.PublicKey = Convert.ToBase64String(pkAsBytes);
        }
    }

    public class PrivateKeyTE : ITableEntity {
        public string PartitionKey { get; set; } = string.Empty;
        public string RowKey { get; set; } = string.Empty;
        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }

        public string? PrivateKey { get; set; }
        public string? PublicKeyId { get; set; }
        public DateTime Expires { get; set; }

        public void AssignePrivateKey(byte[] pkAsBytes) {
            this.PrivateKey = Convert.ToBase64String(pkAsBytes);
        }
    }

    public class RefreshTokenTE : ITableEntity {
        public string PartitionKey { get; set; } = string.Empty;
        public string RowKey { get; set; } = string.Empty;
        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }

        public string? AccessToken { get; set; }
        public DateTime Expires { get; set; }
    }
}