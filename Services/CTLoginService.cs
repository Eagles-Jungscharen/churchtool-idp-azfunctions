using EaglesJungscharen.CT.IDP.Models;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace EaglesJungscharen.CT.IDP.Services {
    public class CTLoginService {
        private string cturl{set;get;}

        public CTLoginService(string url) {
            this.cturl = url;
        }

        public async Task<CTLoginResponse> DoLogin(string userName, string password, HttpClient httpClient) {
            List<KeyValuePair<string,string>> parameters = new List<KeyValuePair<string, string>>();
            parameters.Add(new KeyValuePair<string, string>("username", userName));
            parameters.Add(new KeyValuePair<string, string>("password", password));
            HttpContent content = new FormUrlEncodedContent(parameters);

            HttpResponseMessage response = await httpClient.PostAsync(this.cturl +"/api/login", content);
            if (response.IsSuccessStatusCode) {
                string result = await response.Content.ReadAsStringAsync();
                return JsonConvert.DeserializeObject<CTResponse<CTLoginResponse>>(result).data;
            } else {
                return await buildErrorResponse(response);
            }
        }

        private async Task<CTLoginResponse> buildErrorResponse(HttpResponseMessage response) {
                string result = await response.Content.ReadAsStringAsync();
            CTLoginResponse lr = new CTLoginResponse();
            dynamic res;
            res = JsonConvert.DeserializeObject(result);
            lr.status = "error";
            lr.message = res.message != null ? res.message : response.StatusCode;
            return lr;
        }
    }
}