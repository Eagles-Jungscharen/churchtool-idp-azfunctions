using Azure;
using Azure.Data.Tables;
using System;

namespace EaglesJungscharen.CT.IDP.Models {
    
    public class RefreshTokenTEOOO : ITableEntity {
        public string PartitionKey { get; set; } = string.Empty;
        public string RowKey { get; set; } = string.Empty;
        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }

        public string? AccessToken { get; set; }
        public DateTime Expires { get; set; }
    }
}