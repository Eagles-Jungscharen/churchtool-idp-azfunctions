using Newtonsoft.Json;

namespace EaglesJungscharen.CT.IDP.Models {
    public class CTLoginResponse {
        [JsonProperty("status")]
        public string? Status { get; set; }
        [JsonProperty("message")]
        public string? Message { get; set; }
        [JsonProperty("personId")]
        public int PersonId { get; set; }
    }
} 