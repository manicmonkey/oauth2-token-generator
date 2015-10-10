using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.UI.WebControls;
using Newtonsoft.Json;

namespace OAuth2TokenGenerator
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("OAuth2TokenGenerator for Google APIs. Just returns an access code so you can pipe the output into other commands");
                Console.WriteLine("");
                Console.WriteLine("Usage:");
                Console.WriteLine("  oauth2tokengenerator --key-file=private.p12 --client-email=example@developer.gserviceaccount.com --scopes=https://www.googleapis.com/auth/androidpublisher");
                Console.WriteLine("");
                Console.WriteLine("Options:");
                Console.WriteLine("  --key-file=<path>              Path to private key file (.p12 file)");
                Console.WriteLine("  --client-email=<client-email>  Client Email");
                Console.WriteLine("  --scopes=<scope>[,<scope>]*    Comma delimited authorization scopes");
                Console.WriteLine("  --key-pass=<password>          Optional: private file password [default: notasecret]");
                Console.WriteLine("  --debug                        Optional: enable verbose debug out");
                return;
            }

            var keyFile = GetArgNotNull(args, "--key-file");
            var clientEmail = GetArgNotNull(args, "--client-email");
            var scopes = GetArgNotNull(args, "--scopes").Split(',');
            var keyPass = GetArg(args, "--key-pass", "notasecret");
            var debugging = ArgExists(args, "--debug");
            
            if (debugging)
                Debug.Listeners.Add(new ConsoleTraceListener());

            var accessToken = GetAccessToken(keyFile, keyPass, clientEmail, scopes);
            Console.WriteLine(accessToken);

            if (Debugger.IsAttached)
                Console.ReadLine();
        }

        private static string GetArgNotNull(string[] args, string argName)
        {
            var arg = GetArg(args, argName);
            if (arg == null)
                throw new Exception("Argument '" + argName + "' not supplied");
            return arg;
        }

        private static string GetArg(string[] args, string argName, string defaultValue = null)
        {
            foreach (var arg in args)
            {
                if (arg.StartsWith(argName))
                {
                    return arg.Substring(arg.IndexOf('=') + 1);
                }
            }
            return defaultValue;
        }

        private static bool ArgExists(string[] args, string argName)
        {
            return args.Any(arg => arg.StartsWith(argName));
        }

        public static string GetAccessToken(string privateKeyFile, string privateKeyPassword, string clientEmail, string[] scopes)
        {
            var encodedHeader = GetEncodedJwtHeader();
            var encodedClaimSet = GetEncodedJwtClaimSet(clientEmail, scopes);

            var sig = SignData(privateKeyFile, privateKeyPassword, encodedHeader, encodedClaimSet);
            var jwt = encodedHeader + "." + encodedClaimSet + "." + Base64UrlEncode(sig);
            Debug.WriteLine("Got JWT: " + jwt);

            var formData = BuildFormData(jwt);
            var webRequest = BuildFormPost(formData);
            PostFormData(webRequest, formData);
            var response = ReadResponse(webRequest);
            Debug.WriteLine("Got response: " + response);
            var accessTokenResponse = JsonConvert.DeserializeObject<AccessTokenResponse>(response);
            Debug.WriteLine("Got access token response: " + accessTokenResponse);

            return accessTokenResponse.access_token;
        }

        private static string ReadResponse(WebRequest webRequest)
        {
            try
            {
                using (var response = webRequest.GetResponse())
                using (var responseStream = response.GetResponseStream())
                {
                    if (responseStream == null)
                        throw new Exception("Could not get response - got " + response.Headers);

                    using (var responseReader = new StreamReader(responseStream))
                        return responseReader.ReadToEnd();
                }
            }
            catch (WebException e)
            {
                if (e.Response == null)
                    throw;

                using (var response = e.Response)
                using (var responseStream = response.GetResponseStream())
                {
                    if (responseStream == null)
                        throw;

                    using (var responseReader = new StreamReader(responseStream))
                    {
                        var data = responseReader.ReadToEnd();
                        Console.WriteLine("Got error: " + data);
                        throw;
                    }
                }
            }
        }

        private static void PostFormData(WebRequest webRequest, byte[] formDataBytes)
        {
            var requestStream = webRequest.GetRequestStream();
            requestStream.Write(formDataBytes, 0, formDataBytes.Length);
            requestStream.Close();
        }

        private static HttpWebRequest BuildFormPost(byte[] formDataBytes)
        {
            var webRequest = WebRequest.CreateHttp("https://www.googleapis.com/oauth2/v3/token");
            webRequest.Method = "POST";
            webRequest.ContentType = "application/x-www-form-urlencoded";
            webRequest.ContentLength = formDataBytes.Length;
            return webRequest;
        }

        private static byte[] BuildFormData(string jwt)
        {
            var formData = "grant_type=" + HttpUtility.UrlEncode("urn:ietf:params:oauth:grant-type:jwt-bearer") + "&assertion=" + HttpUtility.UrlEncode(jwt);
            Debug.WriteLine("Form body: " + formData);
            var formDataBytes = System.Text.Encoding.UTF8.GetBytes(formData);
            return formDataBytes;
        }

        private static byte[] SignData(string privateKeyFile, string privateKeyPassword, string encodedHeader, string encodedClaimSet)
        {
            var privKey = GetPrivateKey(privateKeyFile, privateKeyPassword);
            return privKey.SignData(System.Text.Encoding.UTF8.GetBytes(encodedHeader + "." + encodedClaimSet), CryptoConfig.MapNameToOID("SHA256"));
        }

        private static RSACryptoServiceProvider GetPrivateKey(string privateKeyFile, string privateKeyPassword)
        {
            var cert = new X509Certificate2(privateKeyFile, privateKeyPassword);
            var privKey = (RSACryptoServiceProvider)cert.PrivateKey;
            var enhCsp = new RSACryptoServiceProvider().CspKeyContainerInfo;
            var cspparams = new CspParameters(enhCsp.ProviderType, enhCsp.ProviderName, privKey.CspKeyContainerInfo.KeyContainerName);
            return new RSACryptoServiceProvider(cspparams);
        }

        private static string GetEncodedJwtClaimSet(string clientEmail, string[] scopes)
        {
            var secondsSinceEpoch = SecondsSinceEpoch();
            var jwtClaimSet = new JwtClaimSet()
            {
                iss = clientEmail,
                scope = string.Join(" ", scopes),
                aud = "https://www.googleapis.com/oauth2/v3/token",
                exp = secondsSinceEpoch + 120, //two minutes from now
                iat = secondsSinceEpoch
            };

            var claimSet = JsonConvert.SerializeObject(jwtClaimSet);
            Debug.WriteLine("JWT ClaimSet: " + claimSet);
            return Base64UrlEncode(claimSet);
        }

        private static string GetEncodedJwtHeader()
        {
            var jwtHeader = new JwtHeader
            {
                alg = "RS256",
                typ = "JWT"
            };
            var header = JsonConvert.SerializeObject(jwtHeader);
            Debug.WriteLine("JWT Header: " + header);
            return Base64UrlEncode(header);
        }

        private static int SecondsSinceEpoch()
        {
            var timeSpan = DateTime.UtcNow - new DateTime(1970, 1, 1);
            return (int)timeSpan.TotalSeconds;
        }

        private static string Base64UrlEncode(string data)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(data);
            return Base64UrlEncode(bytes);
        }

        static string Base64UrlEncode(byte[] arg)
        {
            string s = Convert.ToBase64String(arg); // Regular base64 encoder
            s = s.Split('=')[0]; // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding
            return s;
        }

        class JwtHeader
        {
            public string alg { get; set; }
            public string typ { get; set; }
        }

        class JwtClaimSet
        {
            public string iss { get; set; }
            public string scope { get; set; }
            public string aud { get; set; }
            public int exp { get; set; }
            public int iat { get; set; }
        }

        class AccessTokenResponse
        {
            public string access_token { get; set; }
            public string token_type { get; set; }
            public int expires_in { get; set; }

            public override string ToString()
            {
                return $"access_token: {access_token}, token_type: {token_type}, expires_in: {expires_in}";
            }
        }
    }
}