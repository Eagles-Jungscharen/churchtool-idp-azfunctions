namespace EaglesJungscharen.CT.IDP.Models {
    public class CTGroup {
        public int domainIdentifier { get; set; }
        public string? title { get; set; }
        public string? domainIdentifierString { get; set; }
    }
    public class CTGroupContainer {
        public CTGroup? group { get; set; }
    }
}