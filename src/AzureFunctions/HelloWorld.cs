using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Host;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using System.Net.Http.Headers;
using System.Threading;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace AzureFunctions
{
    // This requires the JwtBearer authentication nuget package:
    // Install-Package Microsoft.AspNetCore.Authentication.JwtBearer -Version 2.0.0

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