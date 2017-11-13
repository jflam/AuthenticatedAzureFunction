using Microsoft.Identity.Client;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace ConsoleClient
{
    // This requires a reference to the nuget package: MSAL - Microsoft Authentication Library
    // Install-Package Microsoft.Identity.Client -Version 1.1.0-preview
    class Program
    {
        // TODO: this may not even be necessary
        private static string ApplicationId = "23350dde-6e5a-40d4-b200-fce496fd6045";

        // TODO: get URI after deployment
        private static string HelloWorldFunctionUri = "https://jlam-todo-functions.azurewebsites.net/api/HelloWorld?code=3ecR2bqAGHCnjPE0okbJoKcE42sjnqbsJzDpaQNcz6Gyo6pf1aA/aA==";
        private static string LocalHelloWorldFunctionUri = "http://localhost:7071/api/HelloWorld";

        static async Task AuthenticateAndCallAzureFunction()
        {
            var app = new PublicClientApplication(ApplicationId);
            string[] scopes = { "User.Read" };
            var authenticationResult = await app.AcquireTokenAsync(scopes);
            if (authenticationResult != null)
            {
                using (var client = new HttpClient())
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, LocalHelloWorldFunctionUri);
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", authenticationResult.IdToken);

                    HttpResponseMessage response = client.SendAsync(request).Result;

                    var responseString = response.Content.ReadAsStringAsync().Result;
                    Console.WriteLine($"Azure Function returned: {responseString}");
                }
            }
            else
            {
                Console.WriteLine("Unable to get bearer token. Authentication likely failed. Ending.");
            }
        }

        static void Main(string[] args)
        {
            AuthenticateAndCallAzureFunction().Wait();
        }
    }
}
