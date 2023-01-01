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

namespace RedWolf.Hubs
{
    [Authorize]
    public class GrawlHub : Hub
    {
        private readonly IRedWolfService _service;

        public GrawlHub(IRedWolfService service)
        {
            _service = service;
        }

        public async Task JoinGroup(string groupname)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, groupname);
        }

        public async Task GetGrawls()
        {
            List<Grawl> grawls = (await _service.GetGrawls()).Where(G => G.Status != GrawlStatus.Uninitialized).ToList();
            foreach (Grawl g in grawls)
            {
                await this.Clients.Caller.SendAsync("ReceiveGrawl", g.ANOTHERID, g.Name);
            }
        }

        public async Task GetListeners()
        {
            List<Listener> listeners = (await _service.GetListeners()).Where(L => L.Status == ListenerStatus.Active).ToList();
            foreach (Listener l in listeners)
            {
                await this.Clients.Caller.SendAsync("ReceiveListener", l.ANOTHERID, l.Name);
            }
        }

        public async Task GetGrawlLinks()
        {
            List<Grawl> grawls = (await _service.GetGrawls()).Where(G => G.Status != GrawlStatus.Uninitialized && G.Children.Any()).ToList();
            foreach (Grawl g in grawls)
            {
                foreach (string child in g.Children)
                {
                    Grawl childGrawl = await _service.GetGrawlByANOTHERID(child);
                    await this.Clients.Caller.SendAsync("ReceiveGrawlLink", g.ANOTHERID, childGrawl.ANOTHERID);
                }
            }
        }

        public async Task GetGrawlListenerLinks()
        {
            IEnumerable<Grawl> allGrawls = await _service.GetGrawls();
            List<Grawl> grawls = (await _service.GetGrawls())
                .Where(G => G.Status != GrawlStatus.Uninitialized)
                .Where(G => !allGrawls.Any(AG => AG.Children.Contains(G.ANOTHERID)))
                .ToList();
            foreach (Grawl g in grawls)
            {
                Listener l = await _service.GetListener(g.ListenerId);
                await this.Clients.Caller.SendAsync("ReceiveGrawlListenerLink", l.ANOTHERID, g.ANOTHERID);
            }
        }

        public async Task GetInteract(string grawlName, string input)
        {
            RedWolfUser user = await _service.GetUser(this.Context.UserIdentifier);
            Grawl grawl = await _service.GetGrawlByName(grawlName);
            GrawlCommand command = await _service.InteractGrawl(grawl.Id, user.Id, input);
            if (!string.IsNullOrWhiteSpace(command.CommandOutput.Output))
            {
                await this.Clients.Caller.SendAsync("ReceiveCommandOutput", command);
            }
        }

        public async Task GetCommandOutput(int id)
        {
            GrawlCommand command = await _service.GetGrawlCommand(id);
            command.CommandOutput ??= await _service.GetCommandOutput(command.CommandOutputId);
            command.User ??= await _service.GetUser(command.UserId);
            command.GrawlTasking ??= await _service.GetGrawlTasking(command.GrawlTaskingId ?? default);
            if (!string.IsNullOrWhiteSpace(command.CommandOutput.Output))
            {
                await this.Clients.Caller.SendAsync("ReceiveCommandOutput", command);
            }
        }

        public async Task GetSuggestions(string grawlName)
        {
            Grawl grawl = await _service.GetGrawlByName(grawlName);
            List<string> suggestions = await _service.GetCommandSuggestionsForGrawl(grawl);
            await this.Clients.Caller.SendAsync("ReceiveSuggestions", suggestions);
        }
    }
}
