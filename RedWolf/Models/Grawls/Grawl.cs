// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using RedWolf.Core;
using RedWolf.Models.Listeners;

namespace RedWolf.Models.Grawls
{
    public enum GrawlStatus
    {
        Uninitialized,
        Stage0,
        Stage1,
        Stage2,
        Active,
        Lost,
        Exited,
        Disconnected,
        Hidden
    }

    public enum IntegrityLevel
    {
        Untrusted,
        Low,
        Medium,
        High,
        System
    }

    public class Grawl
    {
        // Information to uniquely identify this Grawl
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Name { get; set; } = Utilities.CreateShortGuid();
        [Required]
        public string OriginalServerGuid { get; set; } = Utilities.CreateShortGuid();
        [DisplayName("ANOTHERID")]
        public string ANOTHERID { get; set; }

        // Downstream Grawl ANOTHERIDs
        public List<string> Children { get; set; } = new List<string>();

        // Communication information
        [Required]
        public int ImplantTemplateId { get; set; }
        public ImplantTemplate ImplantTemplate { get; set; }
        [Required]
        public bool ValCerT { get; set; } = true;
        [Required]
        public bool UsCertPin { get; set; } = true;
        [Required, DisplayName("SMBPipeName")]
        public string SMBPipeName { get; set; } = "grawlsvc";

        // Information about the Listener
        public int ListenerId { get; set; }
        public Listener Listener { get; set; }

        // Settings that can be configured
        public string Note { get; set; } = "";
        [Required, Range(0, int.MaxValue)]
        public int Delay { get; set; } = 10;
        [Required, Range(0, 100)]
        public int JItterPercent { get; set; } = 10;
        [Required, Range(0, int.MaxValue)]
        public int ConneCTAttEmpts { get; set; } = 5000;
        [Required]
        public DateTime KillDate { get; set; } = DateTime.MaxValue;

        // Attributes of the remote Grawl
        [Required]
        public Common.DotNetVersion DotNetVersion { get; set; } = Common.DotNetVersion.Net35;
        [Required]
        public Compiler.RuntimeIdentifier RuntimeIdentifier { get; set; } = Compiler.RuntimeIdentifier.win_x64;
        [Required]
        public GrawlStatus Status { get; set; } = GrawlStatus.Uninitialized;
        [Required]
        public IntegrityLevel Integrity { get; set; } = IntegrityLevel.Untrusted;
        public string Process { get; set; } = "";
        public string UserDomainName { get; set; } = "";
        public string UserName { get; set; } = "";
        [DisplayName("IPAddress")]
        public string IPAddress { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string OperatingSystem { get; set; } = "";

        // Information used for authentication or encrypted key exchange
        public string GrawlSharedSecretPassword { get; set; } = Utilities.CreateSecretPassword();
        public string GrawlRSAPublicKey { get; set; } = "";
        public string GrawlNegotiatedSessKEy { get; set; } = "";
        public string GrawlChallenge { get; set; } = "";

        // Time information
        public DateTime ActivationTime { get; set; } = DateTime.MinValue;
        public DateTime LastCheckIn { get; set; } = DateTime.MinValue;

        public string PowerShellImport { get; set; } = "";
        public List<GrawlCommand> GrawlCommands { get; set; } = new List<GrawlCommand>();

        public void AddChild(Grawl grawl)
        {
            if (!string.IsNullOrWhiteSpace(grawl.ANOTHERID))
            {
                this.Children.Add(grawl.ANOTHERID);
            }
        }

        public bool RemoveChild(Grawl grawl)
        {
            return this.Children.Remove(grawl.ANOTHERID);
        }
    }
}
