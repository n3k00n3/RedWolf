using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.SignalR;

using RedWolf.Hubs;
using RedWolf.Models.RedWolf;
using RedWolf.Models.Listeners;
using RedWolf.Models.Launchers;
using RedWolf.Models.Grawls;
using RedWolf.Models.Indicators;

namespace RedWolf.Core
{
    public interface IRedWolfUserNotificationService
    {
        event EventHandler<RedWolfUser> OnCreateRedWolfUser;
        event EventHandler<RedWolfUser> OnEditRedWolfUser;
        event EventHandler<string> OnDeleteRedWolfUser;
        Task NotifyCreateRedWolfUser(object sender, RedWolfUser user);
        Task NotifyEditRedWolfUser(object sender, RedWolfUser user);
        Task NotifyDeleteRedWolfUser(object sender, string id);
    }

    public interface IIdentityRoleNotificationService
    {
        event EventHandler<IdentityRole> OnCreateIdentityRole;
        event EventHandler<IdentityRole> OnEditIdentityRole;
        event EventHandler<string> OnDeleteIdentityRole;
    }

    public interface IIdentityUserRoleNotificationService
    {
        event EventHandler<IdentityUserRole<string>> OnCreateIdentityUserRole;
        event EventHandler<IdentityUserRole<string>> OnEditIdentityUserRole;
        event EventHandler<Tuple<string, string>> OnDeleteIdentityUserRole;
    }

    public interface IThemeNotificationService
    {
        event EventHandler<Theme> OnCreateTheme;
        event EventHandler<Theme> OnEditTheme;
        event EventHandler<int> OnDeleteTheme;
        Task NotifyCreateTheme(object sender, Theme theme);
        Task NotifyEditTheme(object sender, Theme theme);
        Task NotifyDeleteTheme(object sender, int id);
    }

    public interface IEventNotificationService
    {
        event EventHandler<Event> OnCreateEvent;
        event EventHandler<Event> OnEditEvent;
        event EventHandler<int> OnDeleteEvent;
        Task NotifyCreateEvent(object sender, Event anEvent);
    }

    public interface IImplantTemplateNotificationService
    {
        event EventHandler<ImplantTemplate> OnCreateImplantTemplate;
        event EventHandler<ImplantTemplate> OnEditImplantTemplate;
        event EventHandler<int> OnDeleteImplantTemplate;
    }

    public interface IGrawlNotificationService
    {
        event EventHandler<Grawl> OnCreateGrawl;
        event EventHandler<Grawl> OnEditGrawl;
        event EventHandler<int> OnDeleteGrawl;
        Task NotifyCreateGrawl(object sender, Grawl grawl);
        Task NotifyEditGrawl(object sender, Grawl grawl);
    }

    public interface IReferenceAssemblyNotificationService
    {
        event EventHandler<ReferenceAssembly> OnCreateReferenceAssembly;
        event EventHandler<ReferenceAssembly> OnEditReferenceAssembly;
        event EventHandler<int> OnDeleteReferenceAssembly;
    }

    public interface IEmbeddedResourceNotificationService
    {
        event EventHandler<EmbeddedResource> OnCreateEmbeddedResource;
        event EventHandler<EmbeddedResource> OnEditEmbeddedResource;
        event EventHandler<int> OnDeleteEmbeddedResource;
    }

    public interface IReferenceSourceLibraryNotificationService
    {
        event EventHandler<ReferenceSourceLibrary> OnCreateReferenceSourceLibrary;
        event EventHandler<ReferenceSourceLibrary> OnEditReferenceSourceLibrary;
        event EventHandler<int> OnDeleteReferenceSourceLibrary;
    }

    public interface IGrawlTaskOptionNotificationService
    {
        event EventHandler<GrawlTaskOption> OnCreateGrawlTaskOption;
        event EventHandler<GrawlTaskOption> OnEditGrawlTaskOption;
        event EventHandler<int> OnDeleteGrawlTaskOption;
    }

    public interface IGrawlTaskNotificationService : IReferenceAssemblyNotificationService, IEmbeddedResourceNotificationService,
        IReferenceSourceLibraryNotificationService, IGrawlTaskOptionNotificationService
    {
        event EventHandler<GrawlTask> OnCreateGrawlTask;
        event EventHandler<GrawlTask> OnEditGrawlTask;
        event EventHandler<int> OnDeleteGrawlTask;
    }

    public interface IGrawlCommandNotificationService
    {
        event EventHandler<GrawlCommand> OnCreateGrawlCommand;
        event EventHandler<GrawlCommand> OnEditGrawlCommand;
        event EventHandler<int> OnDeleteGrawlCommand;
        Task NotifyCreateGrawlCommand(object sender, GrawlCommand command);
        Task NotifyEditGrawlCommand(object sender, GrawlCommand command);
    }

    public interface ICommandOutputNotificationService
    {
        event EventHandler<CommandOutput> OnCreateCommandOutput;
        event EventHandler<CommandOutput> OnEditCommandOutput;
        event EventHandler<int> OnDeleteCommandOutput;
        Task NotifyEditCommandOutput(object sender, CommandOutput output);
        Task NotifyCreateCommandOutput(object sender, CommandOutput output);
    }

    public interface IGrawlTaskingNotificationService
    {
        event EventHandler<GrawlTasking> OnCreateGrawlTasking;
        event EventHandler<GrawlTasking> OnEditGrawlTasking;
        event EventHandler<int> OnDeleteGrawlTasking;
        Task NotifyCreateGrawlTasking(object sender, GrawlTasking tasking);
        Task NotifyEditGrawlTasking(object sender, GrawlTasking tasking);
    }

    public interface ICredentialNotificationService
    {
        event EventHandler<CapturedCredential> OnCreateCapturedCredential;
        event EventHandler<CapturedCredential> OnEditCapturedCredential;
        event EventHandler<int> OnDeleteCapturedCredential;
    }

    public interface IIndicatorNotificationService
    {
        event EventHandler<Indicator> OnCreateIndicator;
        event EventHandler<Indicator> OnEditIndicator;
        event EventHandler<int> OnDeleteIndicator;
    }

    public interface IListenerTypeNotificationService
    {
        event EventHandler<ListenerType> OnCreateListenerType;
        event EventHandler<ListenerType> OnEditListenerType;
        event EventHandler<int> OnDeleteListenerType;
    }

    public interface IListenerNotificationService : IListenerTypeNotificationService
    {
        event EventHandler<Listener> OnCreateListener;
        event EventHandler<Listener> OnEditListener;
        event EventHandler<int> OnDeleteListener;
        event EventHandler<Grawl> OnNotifyListener;
        Task NotifyNotifyListener(object sender, Grawl grawl);
        Task NotifyCreateListener(object sender, Listener listener);
        Task NotifyEditListener(object sender, Listener listener);
    }

    public interface IProfileNotificationService
    {
        event EventHandler<Profile> OnCreateProfile;
        event EventHandler<Profile> OnEditProfile;
        event EventHandler<int> OnDeleteProfile;
    }

    public interface IHostedFileNotificationService
    {
        event EventHandler<HostedFile> OnCreateHostedFile;
        event EventHandler<HostedFile> OnEditHostedFile;
        event EventHandler<int> OnDeleteHostedFile;
    }

    public interface ILauncherNotificationService
    {
        event EventHandler<Launcher> OnCreateLauncher;
        event EventHandler<Launcher> OnEditLauncher;
        event EventHandler<int> OnDeleteLauncher;
    }

    public interface INotificationService : IRedWolfUserNotificationService, IIdentityRoleNotificationService, IIdentityUserRoleNotificationService, IThemeNotificationService,
        IEventNotificationService, IImplantTemplateNotificationService, IGrawlNotificationService, IGrawlTaskNotificationService,
        IGrawlCommandNotificationService, ICommandOutputNotificationService, IGrawlTaskingNotificationService,
        ICredentialNotificationService, IIndicatorNotificationService, IListenerNotificationService, IProfileNotificationService,
        IHostedFileNotificationService, ILauncherNotificationService
    {
        
    }

    public class NotificationService : INotificationService
    {
        private readonly IHubContext<GrawlHub> _grawlHub;
        private readonly IHubContext<EventHub> _eventHub;
        public NotificationService(IHubContext<GrawlHub> grawlhub, IHubContext<EventHub> eventhub)
        {
            _grawlHub = grawlhub;
            _eventHub = eventhub;
            this.OnNotifyListener += async (sender, egressGrawl) =>
            {
                await _grawlHub.Clients.Group(egressGrawl.Listener.ANOTHERID).SendAsync("NotifyListener", egressGrawl.ANOTHERID);
            };
            this.OnCreateEvent += async (sender, theEvent) => {
                await _eventHub.Clients.Group(theEvent.Context).SendAsync("ReceiveEvent", theEvent);
            };
        }

        public event EventHandler<RedWolfUser> OnCreateRedWolfUser = delegate { };
        public event EventHandler<RedWolfUser> OnEditRedWolfUser = delegate { };
        public event EventHandler<string> OnDeleteRedWolfUser = delegate { };
        public event EventHandler<IdentityRole> OnCreateIdentityRole = delegate { };
        public event EventHandler<IdentityRole> OnEditIdentityRole = delegate { };
        public event EventHandler<string> OnDeleteIdentityRole = delegate { };
        public event EventHandler<IdentityUserRole<string>> OnCreateIdentityUserRole = delegate { };
        public event EventHandler<IdentityUserRole<string>> OnEditIdentityUserRole = delegate { };
        public event EventHandler<Tuple<string, string>> OnDeleteIdentityUserRole = delegate { };
        public event EventHandler<Theme> OnCreateTheme = delegate { };
        public event EventHandler<Theme> OnEditTheme = delegate { };
        public event EventHandler<int> OnDeleteTheme = delegate { };

        public event EventHandler<Event> OnCreateEvent = delegate { };
        public event EventHandler<Event> OnEditEvent = delegate { };
        public event EventHandler<int> OnDeleteEvent = delegate { };
        public event EventHandler<ImplantTemplate> OnCreateImplantTemplate = delegate { };
        public event EventHandler<ImplantTemplate> OnEditImplantTemplate = delegate { };
        public event EventHandler<int> OnDeleteImplantTemplate = delegate { };
        public event EventHandler<Grawl> OnCreateGrawl = delegate { };
        public event EventHandler<Grawl> OnEditGrawl = delegate { };
        public event EventHandler<int> OnDeleteGrawl = delegate { };
        public event EventHandler<ReferenceAssembly> OnCreateReferenceAssembly = delegate { };
        public event EventHandler<ReferenceAssembly> OnEditReferenceAssembly = delegate { };
        public event EventHandler<int> OnDeleteReferenceAssembly = delegate { };
        public event EventHandler<EmbeddedResource> OnCreateEmbeddedResource = delegate { };
        public event EventHandler<EmbeddedResource> OnEditEmbeddedResource = delegate { };
        public event EventHandler<int> OnDeleteEmbeddedResource = delegate { };
        public event EventHandler<ReferenceSourceLibrary> OnCreateReferenceSourceLibrary = delegate { };
        public event EventHandler<ReferenceSourceLibrary> OnEditReferenceSourceLibrary = delegate { };
        public event EventHandler<int> OnDeleteReferenceSourceLibrary = delegate { };
        public event EventHandler<GrawlTaskOption> OnCreateGrawlTaskOption = delegate { };
        public event EventHandler<GrawlTaskOption> OnEditGrawlTaskOption = delegate { };
        public event EventHandler<int> OnDeleteGrawlTaskOption = delegate { };
        public event EventHandler<GrawlTask> OnCreateGrawlTask = delegate { };
        public event EventHandler<GrawlTask> OnEditGrawlTask = delegate { };
        public event EventHandler<int> OnDeleteGrawlTask = delegate { };
        public event EventHandler<GrawlCommand> OnCreateGrawlCommand = delegate { };
        public event EventHandler<GrawlCommand> OnEditGrawlCommand = delegate { };
        public event EventHandler<int> OnDeleteGrawlCommand = delegate { };
        public event EventHandler<CommandOutput> OnCreateCommandOutput = delegate { };
        public event EventHandler<CommandOutput> OnEditCommandOutput = delegate { };
        public event EventHandler<int> OnDeleteCommandOutput = delegate { };
        public event EventHandler<GrawlTasking> OnCreateGrawlTasking = delegate { };
        public event EventHandler<GrawlTasking> OnEditGrawlTasking = delegate { };
        public event EventHandler<int> OnDeleteGrawlTasking = delegate { };
        public event EventHandler<CapturedCredential> OnCreateCapturedCredential = delegate { };
        public event EventHandler<CapturedCredential> OnEditCapturedCredential = delegate { };
        public event EventHandler<int> OnDeleteCapturedCredential = delegate { };
        public event EventHandler<Indicator> OnCreateIndicator = delegate { };
        public event EventHandler<Indicator> OnEditIndicator = delegate { };
        public event EventHandler<int> OnDeleteIndicator = delegate { };
        public event EventHandler<ListenerType> OnCreateListenerType = delegate { };
        public event EventHandler<ListenerType> OnEditListenerType = delegate { };
        public event EventHandler<int> OnDeleteListenerType = delegate { };
        public event EventHandler<Listener> OnCreateListener = delegate { };
        public event EventHandler<Listener> OnEditListener = delegate { };
        public event EventHandler<int> OnDeleteListener = delegate { };
        public event EventHandler<Grawl> OnNotifyListener = delegate { };
        public event EventHandler<Profile> OnCreateProfile = delegate { };
        public event EventHandler<Profile> OnEditProfile = delegate { };
        public event EventHandler<int> OnDeleteProfile = delegate { };
        public event EventHandler<HostedFile> OnCreateHostedFile = delegate { };
        public event EventHandler<HostedFile> OnEditHostedFile = delegate { };
        public event EventHandler<int> OnDeleteHostedFile = delegate { };
        public event EventHandler<Launcher> OnCreateLauncher = delegate { };
        public event EventHandler<Launcher> OnEditLauncher = delegate { };
        public event EventHandler<int> OnDeleteLauncher = delegate { };
        public async Task NotifyCreateRedWolfUser(object sender, RedWolfUser user) { await Task.Run(() => this.OnCreateRedWolfUser(sender, user)); }
        public async Task NotifyEditRedWolfUser(object sender, RedWolfUser user) { await Task.Run(() => this.OnEditRedWolfUser(sender, user)); }
        public async Task NotifyDeleteRedWolfUser(object sender, string id) { await Task.Run(() => this.OnDeleteRedWolfUser(sender, id)); }

        public async Task NotifyCreateTheme(object sender, Theme theme) { await Task.Run(() => this.OnCreateTheme(sender, theme)); }
        public async Task NotifyEditTheme(object sender, Theme theme) { await Task.Run(() => this.OnEditTheme(sender, theme)); }
        public async Task NotifyDeleteTheme(object sender, int id) { await Task.Run(() => this.OnDeleteTheme(sender, id)); }

        public async Task NotifyCreateEvent(object sender, Event anEvent) { await Task.Run(() => this.OnCreateEvent(sender, anEvent)); }

        public async Task NotifyCreateGrawl(object sender, Grawl grawl) { await Task.Run(() => this.OnCreateGrawl(sender, grawl)); }
        public async Task NotifyEditGrawl(object sender, Grawl grawl) { await Task.Run(() => this.OnEditGrawl(sender, grawl)); }

        public async Task NotifyCreateGrawlCommand(object sender, GrawlCommand command) { await Task.Run(() => this.OnCreateGrawlCommand(sender, command)); }
        public async Task NotifyEditGrawlCommand(object sender, GrawlCommand command) { await Task.Run(() => this.OnEditGrawlCommand(sender, command)); }

        public async Task NotifyCreateCommandOutput(object sender, CommandOutput output) { await Task.Run(() => this.OnCreateCommandOutput(sender, output)); }
        public async Task NotifyEditCommandOutput(object sender, CommandOutput output) { await Task.Run(() => this.OnEditCommandOutput(sender, output)); }

        public async Task NotifyCreateGrawlTasking(object sender, GrawlTasking tasking) { await Task.Run(() => this.OnCreateGrawlTasking(sender, tasking)); }
        public async Task NotifyEditGrawlTasking(object sender, GrawlTasking tasking) { await Task.Run(() => this.OnEditGrawlTasking(sender, tasking)); }

        public async Task NotifyNotifyListener(object sender, Grawl grawl) { await Task.Run(() => this.OnNotifyListener(sender, grawl)); }

        public async Task NotifyCreateListener(object sender, Listener listener) { await Task.Run(() => this.OnCreateListener(sender, listener)); }
        public async Task NotifyEditListener(object sender, Listener listener) { await Task.Run(() => this.OnEditListener(sender, listener)); }
    }
}