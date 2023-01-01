// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;

using RedWolf.Core;
using RedWolf.Models.RedWolf;

namespace RedWolf.Models.Grawls
{
    public class CommandOutput
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        public string Output { get; set; } = "";

        [Required]
        public int GrawlCommandId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public GrawlCommand GrawlCommand { get; set; }
    }

    public class GrawlCommand
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Command { get; set; }
        [Required]
        public DateTime CommandTime { get; set; } = DateTime.MinValue;
        [Required]
        public int CommandOutputId { get; set; }
        public CommandOutput CommandOutput { get; set; }

        [Required]
        public string UserId { get; set; }
        public RedWolfUser User { get; set; }

        public int? GrawlTaskingId { get; set; } = null;
        public GrawlTasking GrawlTasking { get; set; }

        public int GrawlId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public Grawl Grawl { get; set; }
    }

    public enum GrawlTaskingStatus
    {
        Uninitialized,
        Tasked,
        Progressed,
        Completed,
        Aborted
    }

    public enum GrawlTaskingType
    {
        Assembly,
        SetDelay,
        SetJItter,
        SetConneCTAttEmpts,
        SetKillDate,
        Exit,
        Connect,
        Disconnect,
        Tasks,
        TaskKill
    }

    public class GrawlTasking
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        [Required]
        public string Name { get; set; } = Utilities.CreateShortGuid();
        [Required]
        public int GrawlId { get; set; }
        public Grawl Grawl { get; set; }
        [Required]
        public int GrawlTaskId { get; set; }
        public GrawlTask GrawlTask { get; set; }

        public GrawlTaskingType Type { get; set; } = GrawlTaskingType.Assembly;
        public List<string> Parameters { get; set; } = new List<string>();

        public GrawlTaskingStatus Status { get; set; } = GrawlTaskingStatus.Uninitialized;
        public DateTime TaskingTime { get; set; } = DateTime.MinValue;
        public DateTime CompletionTime { get; set; } = DateTime.MinValue;

        public int GrawlCommandId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public GrawlCommand GrawlCommand { get; set; }
    }
}
