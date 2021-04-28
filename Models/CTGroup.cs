namespace EaglesJungscharen.CT.IDP.Models {
    public class CTGroup {
        public int domainIdentifier {set;get;}
        public string title {set;get;}
    }
    public class CTGroupContainer {
        public CTGroup group {set;get;}
    }
}