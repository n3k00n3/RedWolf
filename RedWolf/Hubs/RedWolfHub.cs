// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

using RedWolf.Core;
using RedWolf.Models;
using RedWolf.Models.RedWolf;
using RedWolf.Models.Grawls;
using RedWolf.Models.Listeners;
using Microsoft.CodeAnalysis;
using RedWolf.Models.Launchers;
using System.Security.Claims;
using RedWolf.Models.Indicators;
using Microsoft.AspNetCore.Identity;

namespace RedWolf.Hubs
{
    public class RedWolfHub : Hub
    {
        private readonly IRedWolfService _service;

        public RedWolfHub(IRedWolfService service)
        {
            _service = service;
        }
        /*

        public Task<byte[]> CompileGrawlExecutorCode(int id, OutputKind outputKind = OutputKind.DynamicallyLinkedLibrary, bool Compress = false)
        {
            return _service.CompileGrawlExecutorCode(id, outputKind, Compress);
        }

        public Task<byte[]> CompileGrawlStagerCode(int id, Launcher launcher)
        {
            return _service.CompileGrawlStagerCode(id, launcher);
        }

        public Task<BridgeListener> CreateBridgeListener(BridgeListener listener)
        {
            return _service.CreateBridgeListener(listener);
        }

        public Task<BridgeProfile> CreateBridgeProfile(BridgeProfile profile, RedWolfUser currentUser)
        {
            return _service.CreateBridgeProfile(profile, currentUser);
        }

        public Task<CommandOutput> CreateCommandOutput(CommandOutput output)
        {
            return _service.CreateCommandOutput(output);
        }

        public Task<IEnumerable<CommandOutput>> CreateCommandOutputs(params CommandOutput[] outputs)
        {
            return _service.CreateCommandOutputs(outputs);
        }

        public Task<IEnumerable<CapturedCredential>> CreateCredentials(params CapturedCredential[] credentials)
        {
            return _service.CreateCredentials(credentials);
        }

        public Task<DownloadEvent> CreateDownloadEvent(DownloadEvent downloadEvent)
        {
            return _service.CreateDownloadEvent(downloadEvent);
        }

        public Task<EmbeddedResource> CreateEmbeddedResource(EmbeddedResource resource)
        {
            return _service.CreateEmbeddedResource(resource);
        }

        public Task<IEnumerable<EmbeddedResource>> CreateEmbeddedResources(params EmbeddedResource[] resources)
        {
            return _service.CreateEmbeddedResources(resources);
        }

        public Task<Event> CreateEvent(Event anEvent)
        {
            return _service.CreateEvent(anEvent);
        }

        public Task<IEnumerable<Event>> CreateEvents(params Event[] events)
        {
            return _service.CreateEvents(events);
        }

        public Task<Grawl> CreateGrawl(Grawl grawl)
        {
            return _service.CreateGrawl(grawl);
        }

        public Task<GrawlCommand> CreateGrawlCommand(GrawlCommand command)
        {
            return _service.CreateGrawlCommand(command);
        }

        public Task<IEnumerable<GrawlCommand>> CreateGrawlCommands(params GrawlCommand[] commands)
        {
            return _service.CreateGrawlCommands(commands);
        }

        public Task<IEnumerable<Grawl>> CreateGrawls(params Grawl[] grawls)
        {
            return _service.CreateGrawls(grawls);
        }

        public Task<GrawlTask> CreateGrawlTask(GrawlTask task)
        {
            return _service.CreateGrawlTask(task);
        }

        public Task<GrawlTasking> CreateGrawlTasking(GrawlTasking tasking)
        {
            return _service.CreateGrawlTasking(tasking);
        }

        public Task<IEnumerable<GrawlTasking>> CreateGrawlTaskings(params GrawlTasking[] taskings)
        {
            return _service.CreateGrawlTaskings(taskings);
        }

        public Task<GrawlTaskOption> CreateGrawlTaskOption(GrawlTaskOption option)
        {
            return _service.CreateGrawlTaskOption(option);
        }

        public Task<IEnumerable<GrawlTaskOption>> CreateGrawlTaskOptions(params GrawlTaskOption[] options)
        {
            return _service.CreateGrawlTaskOptions(options);
        }

        public Task<IEnumerable<GrawlTask>> CreateGrawlTasks(params GrawlTask[] tasks)
        {
            return _service.CreateGrawlTasks(tasks);
        }

        public Task<CapturedHashCredential> CreateHashCredential(CapturedHashCredential credential)
        {
            return _service.CreateHashCredential(credential);
        }

        public Task<HostedFile> CreateHostedFile(HostedFile file)
        {
            return _service.CreateHostedFile(file);
        }

        public Task<IEnumerable<HostedFile>> CreateHostedFiles(params HostedFile[] files)
        {
            return _service.CreateHostedFiles(files);
        }
        */
        public Task<HttpListener> CreateHttpListener(HttpListener listener)
        {
            return _service.CreateHttpListener(listener);
        }
        /*
        public Task<HttpProfile> CreateHttpProfile(HttpProfile profile, RedWolfUser currentUser)
        {
            return _service.CreateHttpProfile(profile, currentUser);
        }

        public Task<ImplantTemplate> CreateImplantTemplate(ImplantTemplate template)
        {
            return _service.CreateImplantTemplate(template);
        }

        public Task<IEnumerable<ImplantTemplate>> CreateImplantTemplates(params ImplantTemplate[] templates)
        {
            return _service.CreateImplantTemplates(templates);
        }

        public Task<Indicator> CreateIndicator(Indicator indicator)
        {
            return _service.CreateIndicator(indicator);
        }

        public Task<IEnumerable<Indicator>> CreateIndicators(params Indicator[] indicators)
        {
            return _service.CreateIndicators(indicators);
        }

        public Task<IEnumerable<Listener>> CreateListeners(params Listener[] entities)
        {
            return _service.CreateListeners(entities);
        }

        public Task<CapturedPasswordCredential> CreatePasswordCredential(CapturedPasswordCredential credential)
        {
            return _service.CreatePasswordCredential(credential);
        }

        public Task<Profile> CreateProfile(Profile profile, RedWolfUser currentUser)
        {
            return _service.CreateProfile(profile, currentUser);
        }

        public Task<IEnumerable<Profile>> CreateProfiles(params Profile[] profiles)
        {
            return _service.CreateProfiles(profiles);
        }

        public Task<IEnumerable<ReferenceAssembly>> CreateReferenceAssemblies(params ReferenceAssembly[] assemblies)
        {
            return _service.CreateReferenceAssemblies(assemblies);
        }

        public Task<ReferenceAssembly> CreateReferenceAssembly(ReferenceAssembly assembly)
        {
            return _service.CreateReferenceAssembly(assembly);
        }

        public Task<IEnumerable<ReferenceSourceLibrary>> CreateReferenceSourceLibraries(params ReferenceSourceLibrary[] libraries)
        {
            return _service.CreateReferenceSourceLibraries(libraries);
        }

        public Task<ReferenceSourceLibrary> CreateReferenceSourceLibrary(ReferenceSourceLibrary library)
        {
            return _service.CreateReferenceSourceLibrary(library);
        }

        public Task<ScreenshotEvent> CreateScreenshotEvent(ScreenshotEvent screenshotEvent)
        {
            return _service.CreateScreenshotEvent(screenshotEvent);
        }

        public Task<CapturedTicketCredential> CreateTicketCredential(CapturedTicketCredential credential)
        {
            return _service.CreateTicketCredential(credential);
        }

        public Task<RedWolfUser> CreateUser(RedWolfUserLogin login)
        {
            return _service.CreateUser(login);
        }

        public Task<IdentityUserRole<string>> CreateUserRole(string userId, string roleId)
        {
            return _service.CreateUserRole(userId, roleId);
        }

        public Task<RedWolfUser> CreateUserVerify(ClaimsPrincipal principal, RedWolfUserRegister register)
        {
            return _service.CreateUserVerify(principal, register);
        }

        public Task DeleteCommandOutput(int id)
        {
            return _service.DeleteCommandOutput(id);
        }

        public Task DeleteCredential(int credentialId)
        {
            return _service.DeleteCredential(credentialId);
        }

        public Task DeleteEmbeddedResource(int id)
        {
            return _service.DeleteEmbeddedResource(id);
        }

        public Task DeleteGrawl(int grawlId)
        {
            return _service.DeleteGrawl(grawlId);
        }

        public Task DeleteGrawlCommand(int id)
        {
            return _service.DeleteGrawlCommand(id);
        }

        public Task DeleteGrawlTask(int taskId)
        {
            return _service.DeleteGrawlTask(taskId);
        }

        public Task DeleteGrawlTasking(int taskingId)
        {
            return _service.DeleteGrawlTasking(taskingId);
        }

        public Task DeleteHostedFile(int listenerId, int hostedFileId)
        {
            return _service.DeleteHostedFile(listenerId, hostedFileId);
        }

        public Task DeleteImplantTemplate(int id)
        {
            return _service.DeleteImplantTemplate(id);
        }

        public Task DeleteIndicator(int indicatorId)
        {
            return _service.DeleteIndicator(indicatorId);
        }

        public Task DeleteListener(int listenerId)
        {
            return _service.DeleteListener(listenerId);
        }

        public Task DeleteProfile(int id)
        {
            return _service.DeleteProfile(id);
        }

        public Task DeleteReferenceAssembly(int id)
        {
            return _service.DeleteReferenceAssembly(id);
        }

        public Task DeleteReferenceSourceLibrary(int id)
        {
            return _service.DeleteReferenceSourceLibrary(id);
        }

        public Task DeleteUser(string userId)
        {
            return _service.DeleteUser(userId);
        }

        public Task DeleteUserRole(string userId, string roleId)
        {
            return _service.DeleteUserRole(userId, roleId);
        }

        public Task<BinaryLauncher> EditBinaryLauncher(BinaryLauncher launcher)
        {
            return _service.EditBinaryLauncher(launcher);
        }

        public Task<BridgeListener> EditBridgeListener(BridgeListener listener)
        {
            return _service.EditBridgeListener(listener);
        }

        public Task<BridgeProfile> EditBridgeProfile(BridgeProfile profile, RedWolfUser currentUser)
        {
            return _service.EditBridgeProfile(profile, currentUser);
        }

        public Task<CommandOutput> EditCommandOutput(CommandOutput output)
        {
            return _service.EditCommandOutput(output);
        }

        public Task<CscriptLauncher> EditCscriptLauncher(CscriptLauncher launcher)
        {
            return _service.EditCscriptLauncher(launcher);
        }

        public Task<EmbeddedResource> EditEmbeddedResource(EmbeddedResource resource)
        {
            return _service.EditEmbeddedResource(resource);
        }

        public Task<Grawl> EditGrawl(Grawl grawl, RedWolfUser user)
        {
            return _service.EditGrawl(grawl, user);
        }

        public Task<GrawlCommand> EditGrawlCommand(GrawlCommand command)
        {
            return _service.EditGrawlCommand(command);
        }

        public Task<GrawlTask> EditGrawlTask(GrawlTask task)
        {
            return _service.EditGrawlTask(task);
        }

        public Task<GrawlTasking> EditGrawlTasking(GrawlTasking tasking)
        {
            return _service.EditGrawlTasking(tasking);
        }

        public Task<GrawlTaskOption> EditGrawlTaskOption(GrawlTaskOption option)
        {
            return _service.EditGrawlTaskOption(option);
        }

        public Task<CapturedHashCredential> EditHashCredential(CapturedHashCredential credential)
        {
            return _service.EditHashCredential(credential);
        }

        public Task<HostedFile> EditHostedFile(int listenerId, HostedFile file)
        {
            return _service.EditHostedFile(listenerId, file);
        }

        public Task<HttpListener> EditHttpListener(HttpListener listener)
        {
            return _service.EditHttpListener(listener);
        }

        public Task<HttpProfile> EditHttpProfile(HttpProfile profile, RedWolfUser currentUser)
        {
            return _service.EditHttpProfile(profile, currentUser);
        }

        public Task<ImplantTemplate> EditImplantTemplate(ImplantTemplate template)
        {
            return _service.EditImplantTemplate(template);
        }

        public Task<Indicator> EditIndicator(Indicator indicator)
        {
            return _service.EditIndicator(indicator);
        }

        public Task<InstallUtilLauncher> EditInstallUtilLauncher(InstallUtilLauncher launcher)
        {
            return _service.EditInstallUtilLauncher(launcher);
        }

        public Task<Listener> EditListener(Listener listener)
        {
            return _service.EditListener(listener);
        }

        public Task<MSBuildLauncher> EditMSBuildLauncher(MSBuildLauncher launcher)
        {
            return _service.EditMSBuildLauncher(launcher);
        }

        public Task<MshtaLauncher> EditMshtaLauncher(MshtaLauncher launcher)
        {
            return _service.EditMshtaLauncher(launcher);
        }

        public Task<CapturedPasswordCredential> EditPasswordCredential(CapturedPasswordCredential credential)
        {
            return _service.EditPasswordCredential(credential);
        }

        public Task<PowerShellLauncher> EditPowerShellLauncher(PowerShellLauncher launcher)
        {
            return _service.EditPowerShellLauncher(launcher);
        }

        public Task<Profile> EditProfile(Profile profile, RedWolfUser currentUser)
        {
            return _service.EditProfile(profile, currentUser);
        }

        public Task<ReferenceAssembly> EditReferenceAssembly(ReferenceAssembly assembly)
        {
            return _service.EditReferenceAssembly(assembly);
        }

        public Task<ReferenceSourceLibrary> EditReferenceSourceLibrary(ReferenceSourceLibrary library)
        {
            return _service.EditReferenceSourceLibrary(library);
        }

        public Task<Regsvr32Launcher> EditRegsvr32Launcher(Regsvr32Launcher launcher)
        {
            return _service.EditRegsvr32Launcher(launcher);
        }

        public Task<CapturedTicketCredential> EditTicketCredential(CapturedTicketCredential credential)
        {
            return _service.EditTicketCredential(credential);
        }

        public Task<RedWolfUser> EditUser(RedWolfUser currentUser, RedWolfUserLogin user)
        {
            return _service.EditUser(currentUser, user);
        }

        public Task<WmicLauncher> EditWmicLauncher(WmicLauncher launcher)
        {
            return _service.EditWmicLauncher(launcher);
        }

        public Task<WscriptLauncher> EditWscriptLauncher(WscriptLauncher launcher)
        {
            return _service.EditWscriptLauncher(launcher);
        }

        public Task<BinaryLauncher> GenerateBinaryHostedLauncher(HostedFile file)
        {
            return _service.GenerateBinaryHostedLauncher(file);
        }

        public Task<BinaryLauncher> GenerateBinaryLauncher()
        {
            return _service.GenerateBinaryLauncher();
        }

        public Task<CscriptLauncher> GenerateCscriptHostedLauncher(HostedFile file)
        {
            return _service.GenerateCscriptHostedLauncher(file);
        }

        public Task<CscriptLauncher> GenerateCscriptLauncher()
        {
            return _service.GenerateCscriptLauncher();
        }

        public Task<InstallUtilLauncher> GenerateInstallUtilHostedLauncher(HostedFile file)
        {
            return _service.GenerateInstallUtilHostedLauncher(file);
        }

        public Task<InstallUtilLauncher> GenerateInstallUtilLauncher()
        {
            return _service.GenerateInstallUtilLauncher();
        }

        public Task<MSBuildLauncher> GenerateMSBuildHostedLauncher(HostedFile file)
        {
            return _service.GenerateMSBuildHostedLauncher(file);
        }

        public Task<MSBuildLauncher> GenerateMSBuildLauncher()
        {
            return _service.GenerateMSBuildLauncher();
        }

        public Task<MshtaLauncher> GenerateMshtaHostedLauncher(HostedFile file)
        {
            return _service.GenerateMshtaHostedLauncher(file);
        }

        public Task<MshtaLauncher> GenerateMshtaLauncher()
        {
            return _service.GenerateMshtaLauncher();
        }

        public Task<PowerShellLauncher> GeneratePowerShellHostedLauncher(HostedFile file)
        {
            return _service.GeneratePowerShellHostedLauncher(file);
        }

        public Task<PowerShellLauncher> GeneratePowerShellLauncher()
        {
            return _service.GeneratePowerShellLauncher();
        }

        public Task<Regsvr32Launcher> GenerateRegsvr32HostedLauncher(HostedFile file)
        {
            return _service.GenerateRegsvr32HostedLauncher(file);
        }

        public Task<Regsvr32Launcher> GenerateRegsvr32Launcher()
        {
            return _service.GenerateRegsvr32Launcher();
        }

        public Task<WmicLauncher> GenerateWmicHostedLauncher(HostedFile file)
        {
            return _service.GenerateWmicHostedLauncher(file);
        }

        public Task<WmicLauncher> GenerateWmicLauncher()
        {
            return _service.GenerateWmicLauncher();
        }

        public Task<WscriptLauncher> GenerateWscriptHostedLauncher(HostedFile file)
        {
            return _service.GenerateWscriptHostedLauncher(file);
        }

        public Task<WscriptLauncher> GenerateWscriptLauncher()
        {
            return _service.GenerateWscriptLauncher();
        }

        public Task<BinaryLauncher> GetBinaryLauncher()
        {
            return _service.GetBinaryLauncher();
        }

        public Task<BridgeListener> GetBridgeListener(int listenerId)
        {
            return _service.GetBridgeListener(listenerId);
        }

        public Task<IEnumerable<BridgeListener>> GetBridgeListeners()
        {
            return _service.GetBridgeListeners();
        }

        public Task<BridgeProfile> GetBridgeProfile(int profileId)
        {
            return _service.GetBridgeProfile(profileId);
        }

        public Task<IEnumerable<BridgeProfile>> GetBridgeProfiles()
        {
            return _service.GetBridgeProfiles();
        }

        public Task<CommandOutput> GetCommandOutput(int commandOutputId)
        {
            return _service.GetCommandOutput(commandOutputId);
        }

        public Task<IEnumerable<CommandOutput>> GetCommandOutputs()
        {
            return _service.GetCommandOutputs();
        }

        public Task<List<string>> GetCommandSuggestionsForGrawl(Grawl grawl)
        {
            return _service.GetCommandSuggestionsForGrawl(grawl);
        }

        public Task<CapturedCredential> GetCredential(int credentialId)
        {
            return _service.GetCredential(credentialId);
        }

        public Task<IEnumerable<CapturedCredential>> GetCredentials()
        {
            return _service.GetCredentials();
        }

        public Task<CscriptLauncher> GetCscriptLauncher()
        {
            return _service.GetCscriptLauncher();
        }

        public Task<RedWolfUser> GetCurrentUser(ClaimsPrincipal principal)
        {
            return _service.GetCurrentUser(principal);
        }

        public Task<IEnumerable<ReferenceAssembly>> GetDefaultNet35ReferenceAssemblies()
        {
            return _service.GetDefaultNet35ReferenceAssemblies();
        }

        public Task<IEnumerable<ReferenceAssembly>> GetDefaultNet40ReferenceAssemblies()
        {
            return _service.GetDefaultNet40ReferenceAssemblies();
        }

        public Task<string> GetDownloadContent(int eventId)
        {
            return _service.GetDownloadContent(eventId);
        }

        public Task<DownloadEvent> GetDownloadEvent(int eventId)
        {
            return _service.GetDownloadEvent(eventId);
        }

        public Task<IEnumerable<DownloadEvent>> GetDownloadEvents()
        {
            return _service.GetDownloadEvents();
        }

        public Task<EmbeddedResource> GetEmbeddedResource(int id)
        {
            return _service.GetEmbeddedResource(id);
        }

        public Task<EmbeddedResource> GetEmbeddedResourceByName(string name)
        {
            return _service.GetEmbeddedResourceByName(name);
        }

        public Task<IEnumerable<EmbeddedResource>> GetEmbeddedResources()
        {
            return _service.GetEmbeddedResources();
        }

        public Task<Event> GetEvent(int eventId)
        {
            return _service.GetEvent(eventId);
        }

        public Task<IEnumerable<Event>> GetEvents()
        {
            return _service.GetEvents();
        }

        public Task<IEnumerable<Event>> GetEventsAfter(long fromdate)
        {
            return _service.GetEventsAfter(fromdate);
        }

        public Task<IEnumerable<Event>> GetEventsRange(long fromdate, long todate)
        {
            return _service.GetEventsRange(fromdate, todate);
        }

        public Task<long> GetEventTime()
        {
            return _service.GetEventTime();
        }

        public Task<FileIndicator> GetFileIndicator(int indicatorId)
        {
            return _service.GetFileIndicator(indicatorId);
        }

        public Task<IEnumerable<FileIndicator>> GetFileIndicators()
        {
            return _service.GetFileIndicators();
        }

        public Task<Grawl> GetGrawl(int grawlId)
        {
            return _service.GetGrawl(grawlId);
        }

        public Task<Grawl> GetGrawlByANOTHERID(string anotherid)
        {
            return _service.GetGrawlByANOTHERID(anotherid);
        }

        public Task<Grawl> GetGrawlByName(string name, StringComparison compare = StringComparison.CurrentCulture)
        {
            return _service.GetGrawlByName(name, compare);
        }

        public Task<Grawl> GetGrawlByOriginalServerANOTHERID(string serveranotherid)
        {
            return _service.GetGrawlByOriginalServerANOTHERID(serveranotherid);
        }

        public Task<GrawlCommand> GetGrawlCommand(int id)
        {
            return _service.GetGrawlCommand(id);
        }

        public Task<IEnumerable<GrawlCommand>> GetGrawlCommands()
        {
            return _service.GetGrawlCommands();
        }

        public Task<IEnumerable<GrawlCommand>> GetGrawlCommandsForGrawl(int grawlId)
        {
            return _service.GetGrawlCommandsForGrawl(grawlId);
        }

        public Task<IEnumerable<Grawl>> GetGrawls()
        {
            return _service.GetGrawls();
        }

        public Task<GrawlTask> GetGrawlTask(int id)
        {
            return _service.GetGrawlTask(id);
        }

        public Task<GrawlTask> GetGrawlTaskByName(string name, Common.DotNetVersion version = Common.DotNetVersion.Net35)
        {
            return _service.GetGrawlTaskByName(name, version);
        }

        public Task<GrawlTasking> GetGrawlTasking(int taskingId)
        {
            return _service.GetGrawlTasking(taskingId);
        }

        public Task<GrawlTasking> GetGrawlTaskingByName(string taskingName)
        {
            return _service.GetGrawlTaskingByName(taskingName);
        }

        public Task<IEnumerable<GrawlTasking>> GetGrawlTaskings()
        {
            return _service.GetGrawlTaskings();
        }

        public Task<IEnumerable<GrawlTasking>> GetGrawlTaskingsForGrawl(int grawlId)
        {
            return _service.GetGrawlTaskingsForGrawl(grawlId);
        }

        public Task<IEnumerable<GrawlTasking>> GetGrawlTaskingsSearch(int grawlId)
        {
            return _service.GetGrawlTaskingsSearch(grawlId);
        }

        public Task<IEnumerable<GrawlTask>> GetGrawlTasks()
        {
            return _service.GetGrawlTasks();
        }

        public Task<IEnumerable<GrawlTask>> GetGrawlTasksForGrawl(int grawlId)
        {
            return _service.GetGrawlTasksForGrawl(grawlId);
        }

        public Task<CapturedHashCredential> GetHashCredential(int credentialId)
        {
            return _service.GetHashCredential(credentialId);
        }

        public Task<IEnumerable<CapturedHashCredential>> GetHashCredentials()
        {
            return _service.GetHashCredentials();
        }

        public Task<HostedFile> GetHostedFile(int hostedFileId)
        {
            return _service.GetHostedFile(hostedFileId);
        }

        public Task<HostedFile> GetHostedFileForListener(int listenerId, int hostedFileId)
        {
            return _service.GetHostedFileForListener(listenerId, hostedFileId);
        }

        public Task<IEnumerable<HostedFile>> GetHostedFiles()
        {
            return _service.GetHostedFiles();
        }

        public Task<IEnumerable<HostedFile>> GetHostedFilesForListener(int listenerId)
        {
            return _service.GetHostedFilesForListener(listenerId);
        }

        public Task<HttpListener> GetHttpListener(int listenerId)
        {
            return _service.GetHttpListener(listenerId);
        }

        public Task<IEnumerable<HttpListener>> GetHttpListeners()
        {
            return _service.GetHttpListeners();
        }

        public Task<HttpProfile> GetHttpProfile(int profileId)
        {
            return _service.GetHttpProfile(profileId);
        }

        public Task<IEnumerable<HttpProfile>> GetHttpProfiles()
        {
            return _service.GetHttpProfiles();
        }

        public Task<ImplantTemplate> GetImplantTemplate(int id)
        {
            return _service.GetImplantTemplate(id);
        }

        public Task<ImplantTemplate> GetImplantTemplateByName(string name)
        {
            return _service.GetImplantTemplateByName(name);
        }

        public Task<IEnumerable<ImplantTemplate>> GetImplantTemplates()
        {
            return _service.GetImplantTemplates();
        }

        public Task<Indicator> GetIndicator(int indicatorId)
        {
            return _service.GetIndicator(indicatorId);
        }

        public Task<IEnumerable<Indicator>> GetIndicators()
        {
            return _service.GetIndicators();
        }

        public Task<InstallUtilLauncher> GetInstallUtilLauncher()
        {
            return _service.GetInstallUtilLauncher();
        }

        public Task<Launcher> GetLauncher(int id)
        {
            return _service.GetLauncher(id);
        }

        public Task<IEnumerable<Launcher>> GetLaunchers()
        {
            return _service.GetLaunchers();
        }

        public Task<Listener> GetListener(int listenerId)
        {
            return _service.GetListener(listenerId);
        }

        public Task<IEnumerable<Listener>> GetListeners()
        {
            return _service.GetListeners();
        }

        public Task<ListenerType> GetListenerType(int listenerTypeId)
        {
            return _service.GetListenerType(listenerTypeId);
        }

        public Task<ListenerType> GetListenerTypeByName(string name)
        {
            return _service.GetListenerTypeByName(name);
        }

        public Task<IEnumerable<ListenerType>> GetListenerTypes()
        {
            return _service.GetListenerTypes();
        }

        public Task<MSBuildLauncher> GetMSBuildLauncher()
        {
            return _service.GetMSBuildLauncher();
        }

        public Task<MshtaLauncher> GetMshtaLauncher()
        {
            return _service.GetMshtaLauncher();
        }

        public Task<NetworkIndicator> GetNetworkIndicator(int indicatorId)
        {
            return _service.GetNetworkIndicator(indicatorId);
        }

        public Task<IEnumerable<NetworkIndicator>> GetNetworkIndicators()
        {
            return _service.GetNetworkIndicators();
        }

        public Task<Grawl> GetOutboundGrawl(int grawlId)
        {
            return _service.GetOutboundGrawl(grawlId);
        }

        public Task<CapturedPasswordCredential> GetPasswordCredential(int credentialId)
        {
            return _service.GetPasswordCredential(credentialId);
        }

        public Task<IEnumerable<CapturedPasswordCredential>> GetPasswordCredentials()
        {
            return _service.GetPasswordCredentials();
        }

        public Task<List<string>> GetPathToChildGrawl(int grawlId, int childId)
        {
            return _service.GetPathToChildGrawl(grawlId, childId);
        }

        public Task<PowerShellLauncher> GetPowerShellLauncher()
        {
            return _service.GetPowerShellLauncher();
        }

        public Task<Profile> GetProfile(int profileId)
        {
            return _service.GetProfile(profileId);
        }

        public Task<IEnumerable<Profile>> GetProfiles()
        {
            return _service.GetProfiles();
        }

        public Task<IEnumerable<ReferenceAssembly>> GetReferenceAssemblies()
        {
            return _service.GetReferenceAssemblies();
        }

        public Task<ReferenceAssembly> GetReferenceAssembly(int id)
        {
            return _service.GetReferenceAssembly(id);
        }

        public Task<ReferenceAssembly> GetReferenceAssemblyByName(string name, Common.DotNetVersion version)
        {
            return _service.GetReferenceAssemblyByName(name, version);
        }

        public Task<IEnumerable<ReferenceSourceLibrary>> GetReferenceSourceLibraries()
        {
            return _service.GetReferenceSourceLibraries();
        }

        public Task<ReferenceSourceLibrary> GetReferenceSourceLibrary(int id)
        {
            return _service.GetReferenceSourceLibrary(id);
        }

        public Task<ReferenceSourceLibrary> GetReferenceSourceLibraryByName(string name)
        {
            return _service.GetReferenceSourceLibraryByName(name);
        }

        public Task<Regsvr32Launcher> GetRegsvr32Launcher()
        {
            return _service.GetRegsvr32Launcher();
        }

        public Task<IdentityRole> GetRole(string roleId)
        {
            return _service.GetRole(roleId);
        }

        public Task<IdentityRole> GetRoleByName(string rolename)
        {
            return _service.GetRoleByName(rolename);
        }

        public Task<IEnumerable<IdentityRole>> GetRoles()
        {
            return _service.GetRoles();
        }

        public Task<string> GetScreenshotContent(int eventId)
        {
            return _service.GetScreenshotContent(eventId);
        }

        public Task<ScreenshotEvent> GetScreenshotEvent(int eventId)
        {
            return _service.GetScreenshotEvent(eventId);
        }

        public Task<IEnumerable<ScreenshotEvent>> GetScreenshotEvents()
        {
            return _service.GetScreenshotEvents();
        }

        public Task<TargetIndicator> GetTargetIndicator(int indicatorId)
        {
            return _service.GetTargetIndicator(indicatorId);
        }

        public Task<IEnumerable<TargetIndicator>> GetTargetIndicators()
        {
            return _service.GetTargetIndicators();
        }

        public Task<CapturedTicketCredential> GetTicketCredential(int credentialId)
        {
            return _service.GetTicketCredential(credentialId);
        }

        public Task<IEnumerable<CapturedTicketCredential>> GetTicketCredentials()
        {
            return _service.GetTicketCredentials();
        }

        public Task<IEnumerable<GrawlTasking>> GetUninitializedGrawlTaskingsForGrawl(int grawlId)
        {
            return _service.GetUninitializedGrawlTaskingsForGrawl(grawlId);
        }

        public Task<RedWolfUser> GetUser(string userId)
        {
            return _service.GetUser(userId);
        }

        public Task<RedWolfUser> GetUserByUsername(string username)
        {
            return _service.GetUserByUsername(username);
        }

        public Task<IdentityUserRole<string>> GetUserRole(string userId, string roleId)
        {
            return _service.GetUserRole(userId, roleId);
        }

        public Task<IEnumerable<IdentityUserRole<string>>> GetUserRoles()
        {
            return _service.GetUserRoles();
        }

        public Task<IEnumerable<IdentityUserRole<string>>> GetUserRolesForUser(string userId)
        {
            return _service.GetUserRolesForUser(userId);
        }

        public Task<IEnumerable<RedWolfUser>> GetUsers()
        {
            return _service.GetUsers();
        }

        public Task<WmicLauncher> GetWmicLauncher()
        {
            return _service.GetWmicLauncher();
        }

        public Task<WscriptLauncher> GetWscriptLauncher()
        {
            return _service.GetWscriptLauncher();
        }

        public Task<GrawlCommand> InteractGrawl(int GrawlId, string UserId, string UserInput)
        {
            return _service.InteractGrawl(GrawlId, UserId, UserInput);
        }

        public Task<bool> IsGrawlLost(Grawl g)
        {
            return _service.IsGrawlLost(g);
        }

        public Task<RedWolfUserLoginResult> Login(RedWolfUserLogin login)
        {
            return _service.Login(login);
        }

        public Task StartListener(int listenerId)
        {
            return _service.StartListener(listenerId);
        }

        public Task<string> ParseParametersIntoTask(GrawlTask task, List<ParsedParameter> parameters)
        {
            return _service.ParseParametersIntoTask(task, parameters);
        }

        public Task<GrawlTaskAuthor> GetGrawlTaskAuthor(int id)
        {
            return _service.GetGrawlTaskAuthor(id);
        }

        public Task<GrawlTaskAuthor> GetGrawlTaskAuthorByName(string Name)
        {
            return _service.GetGrawlTaskAuthorByName(Name);
        }

        public Task<IEnumerable<GrawlTaskAuthor>> GetGrawlTaskAuthors()
        {
            return _service.GetGrawlTaskAuthors();
        }

        public Task<GrawlTaskAuthor> CreateGrawlTaskAuthor(GrawlTaskAuthor author)
        {
            return _service.CreateGrawlTaskAuthor(author);
        }

        public Task<GrawlTaskAuthor> EditGrawlTaskAuthor(GrawlTaskAuthor author)
        {
            return _service.EditGrawlTaskAuthor(author);
        }
        */
    }
}
