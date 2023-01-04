using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Rest;
using Microsoft.Extensions.Configuration;

using RedWolf.API;
using RedWolf.Models.Listeners;

namespace RedWolf.Core
{
    public class RedWolfAPIService
    {
        private readonly RedWolfAPI _client;

        public RedWolfAPIService(IConfiguration configuration)
        {
            X509Certificate2 redwolfCert = new X509Certificate2(Common.RedWolfPublicCertFile);
            HttpClientHandler clientHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
                {
                    return cert.GetCertHashString() == redwolfCert.GetCertHashString();
                }
            };
            _client = new RedWolfAPI(
                new Uri("https://localhost:" + configuration["RedWolfPort"]),
                new TokenCredentials(configuration["ServiceUserToken"]),
                clientHandler
            );
        }

        public async Task CreateHttpListener(HttpListener listener)
        {
            await _client.CreateHttpListenerAsync(ToAPIListener(listener));
        }

        public async Task CreateBridgeListener(BridgeListener listener)
        {
            await _client.CreateBridgeListenerAsync(ToAPIListener(listener));
        }

        public static RedWolf.API.Models.HttpListener ToAPIListener(HttpListener listener)
        {
            return new RedWolf.API.Models.HttpListener
            {
                Id = listener.Id,
                Name = listener.Name,
                BindAddress = listener.BindAddress,
                BindPort = listener.BindPort,
                ConnectAddresses = listener.ConnectAddresses,
                ConnectPort = listener.ConnectPort,
                RedWolfUrl = listener.RedWolfUrl,
                RedWolfToken = listener.RedWolfToken,
                Description = listener.Description,
                Guid = listener.ANOTHERID,
                ListenerTypeId = listener.ListenerTypeId,
                ProfileId = listener.ProfileId,
                SslCertHash = listener.SSLCertHash,
                SslCertificate = listener.SSLCertificate,
                SslCertificatePassword = listener.SSLCertificatePassword,
                StartTime = listener.StartTime,
                Status = (RedWolf.API.Models.ListenerStatus)Enum.Parse(typeof(RedWolf.API.Models.ListenerStatus), listener.Status.ToString(), true),
                Urls = listener.Urls,
                UseSSL = listener.UseSSL
            };
        }

        public static RedWolf.API.Models.BridgeListener ToAPIListener(BridgeListener listener)
        {
            return new RedWolf.API.Models.BridgeListener
            {
                Id = listener.Id,
                Name = listener.Name,
                BindAddress = listener.BindAddress,
                BindPort = listener.BindPort,
                ConnectAddresses = listener.ConnectAddresses,
                ConnectPort = listener.ConnectPort,
                RedWolfUrl = listener.RedWolfUrl,
                RedWolfToken = listener.RedWolfToken,
                Description = listener.Description,
                Guid = listener.ANOTHERID,
                IsBridgeConnected = listener.IsBridgeConnected,
                ImplantReadCode = listener.ImplantReadCode,
                ImplantWriteCode = listener.ImplantWriteCode,
                ListenerTypeId = listener.ListenerTypeId,
                ProfileId = listener.ProfileId,
                StartTime = listener.StartTime,
                Status = (RedWolf.API.Models.ListenerStatus)Enum.Parse(typeof(RedWolf.API.Models.ListenerStatus), listener.Status.ToString(), true)
            };
        }
    }
}