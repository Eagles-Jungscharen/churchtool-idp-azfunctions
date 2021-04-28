using EaglesJungscharen.CT.IDP.Models;
using System.Net.Http;
using System.Net;
using System.Threading.Tasks;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.Linq;
using System;

namespace EaglesJungscharen.CT.IDP.Services {
    public class CTLoginService {
        private string cturl{set;get;}

        public CTLoginService(string url) {
            this.cturl = url;
        }

        public async Task<LoginResult> DoLogin(string userName, string password, HttpClient httpClient) {
            List<KeyValuePair<string,string>> parameters = new List<KeyValuePair<string, string>>();
            parameters.Add(new KeyValuePair<string, string>("username", userName));
            parameters.Add(new KeyValuePair<string, string>("password", password));
            HttpContent content = new FormUrlEncodedContent(parameters);

            HttpResponseMessage response = await httpClient.PostAsync(this.cturl +"/api/login", content);
            if (response.IsSuccessStatusCode) {
                string result = await response.Content.ReadAsStringAsync();
                CTLoginResponse cTLoginResponse= JsonConvert.DeserializeObject<CTResponse<CTLoginResponse>>(result).data;
                string cookieHeaders ="";
                IEnumerable<string> cookHeaderValues;
                if (response.Headers.TryGetValues("Set-Cookie", out cookHeaderValues)) {
                    cookieHeaders = cookHeaderValues.First();
                }
                return new LoginResult() {
                    Error = false,
                    CTLoginResponse = cTLoginResponse,
                    SetCookieHeader = cookieHeaders
                };
            } else {
                return await buildErrorResponse(response);
            }
        }

        private async Task<LoginResult> buildErrorResponse(HttpResponseMessage response) {
            string result = await response.Content.ReadAsStringAsync();
            dynamic res;
            LoginResult lr = new LoginResult();
            res = JsonConvert.DeserializeObject(result);
            lr.Error = true;
            lr.ErrorMessage = res.message != null ? res.message : response.StatusCode;
            return lr;
        }

        public async Task<CTWhoami> GetWhoAmi(string setCookieHeader, HttpClient httpClient) {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, this.cturl +"/api/whoami?only_allow_authenticated=true");
            CookieContainer container = new CookieContainer();
            Uri ctUri = new Uri(this.cturl);
            container.SetCookies(ctUri, setCookieHeader );
            request.Headers.Add("Cookie",container.GetCookieHeader(ctUri));
            HttpResponseMessage response = await httpClient.SendAsync(request);
            string result = await response.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<CTResponse<CTWhoami>>(result).data;            
        }

        public async Task<List<CTGroupContainer>> GetGroups(string setCookieHeader, int id, HttpClient httpClient) {
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, this.cturl +"/api/persons/"+id+"/groups");
            CookieContainer container = new CookieContainer();
            Uri ctUri = new Uri(this.cturl);
            container.SetCookies(ctUri, setCookieHeader );
            request.Headers.Add("Cookie",container.GetCookieHeader(ctUri));
            HttpResponseMessage response = await httpClient.SendAsync(request);
            string result = await response.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<CTResponse<List<CTGroupContainer>>>(result).data;           
        }
    }
}