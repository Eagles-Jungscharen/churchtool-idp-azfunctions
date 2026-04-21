using Newtonsoft.Json;

namespace EaglesJungscharen.CT.IDP.Models {
    public class CTResponse<T> {
        [JsonProperty("data")]
        public T? Data { get; set; }
    }
}