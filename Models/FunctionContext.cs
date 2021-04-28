using Microsoft.Extensions.Logging;
using Microsoft.Azure.Cosmos.Table;
using Microsoft.AspNetCore.Http;

namespace EaglesJungscharen.CT.IDP.Models {
    public class FunctionContext<T> {
        public ILogger Log {get;}
        public HttpRequest Request {get;}
        public CloudTable Table {get;}

        public T PayLoad {set;get;}

        public FunctionContext(ILogger logger, HttpRequest request, CloudTable table){
            this.Log = logger;
            this.Request = request;
            this.Table = table;
        } 
    }
}