using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace AzureFunctions
{
    // This requires the JwtBearer authentication nuget package:
    // Install-Package Microsoft.AspNetCore.Authentication.JwtBearer -Version 2.0.0

    // For local development, you'll need to have node.js runtime installed, as well as the Azure Functions runtime
    // npm install -g azure-functions-core-tools

    // Credit for much of the code in the Security class goes to this blog post by Boris Wilhelms:
    // https://blog.wille-zone.de/post/secure-azure-functions-with-jwt-token/
    // Modifications by me to correctly authorize the MSA account programmatically. 

    public static class Security
    {
        public static readonly IConfigurationManager<OpenIdConnectConfiguration> _configurationManager;
        public static string ISSUER = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0";

        static Security()
        {
            var issuer = ISSUER;
            var documentRetriever = new HttpDocumentRetriever();
            documentRetriever.RequireHttps = issuer.StartsWith("https://");

            _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{issuer}/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(),
                documentRetriever
            );
        }

        public static async Task<ClaimsPrincipal> ValidateTokenAsync(AuthenticationHeaderValue value)
        {
            if (value?.Scheme != "Bearer")
            {
                return null;
            }

            var config = await _configurationManager.GetConfigurationAsync(CancellationToken.None);

            var validationParameter = new TokenValidationParameters()
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                SaveSigninToken = false,
                ValidateActor = false,
                ValidateAudience = false,
                ValidateIssuer = true,
                ValidIssuer = ISSUER,
                ValidateIssuerSigningKey = false,
                ValidateLifetime = true,
                IssuerSigningKeys = config.SigningKeys
            };

            ClaimsPrincipal result = null;
            var tries = 0;

            while (result == null && tries <= 1)
            {
                try
                {
                    var handler = new JwtSecurityTokenHandler();
                    result = handler.ValidateToken(value.Parameter, validationParameter, out var token);
                }
                catch (SecurityTokenSignatureKeyNotFoundException)
                {
                    _configurationManager.RequestRefresh();
                    tries++;
                }
                catch (SecurityTokenException)
                {
                    return null;
                }
            }

            return result;
        }
    }

    public static class HelloWorld
    {
        [FunctionName("HelloWorld")]
        public static async Task<HttpResponseMessage> Run([HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)]HttpRequestMessage req, TraceWriter log)
        {
            ClaimsPrincipal principal;
            if ((principal = await Security.ValidateTokenAsync(req.Headers.Authorization)) == null)
            {
                return req.CreateResponse(HttpStatusCode.Unauthorized);
            }
            else
            {
                var username = principal.Claims.FirstOrDefault(c => c.Type == "preferred_username");

                // Of course this is not scalable, but the goal is to demonstrate programmatic access.
                if (username.Value == "jlam@iunknown.com")
                {
                    return req.CreateResponse(HttpStatusCode.OK, "Hello, World!");
                }
                else
                {
                    return req.CreateResponse(HttpStatusCode.Unauthorized);
                }
            }
        }
    }
}