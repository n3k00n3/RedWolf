using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Newtonsoft.Json;
using YamlDotNet.Serialization;

namespace RedWolf.Models.Grawls
{
    public class GrawlTaskOption : ISerializable<GrawlTaskOption>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public string DefaultValue { get; set; } = "";
        public string Description { get; set; } = "";
        public List<string> SuggestedValues { get; set; } = new List<string>();
        public bool Optional { get; set; } = false;
        public bool DisplayInCommand { get; set; } = true;
        public bool FileOption { get; set; } = false;

        public int GrawlTaskId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public GrawlTask Task { get; set; }

        internal SerializedGrawlTaskOption ToSerializedGrawlTaskOption()
        {
            return new SerializedGrawlTaskOption
            {
                Name = this.Name,
                Value = "",
                DefaultValue = this.DefaultValue,
                Description = this.Description,
                SuggestedValues = this.SuggestedValues,
                Optional = this.Optional,
                DisplayInCommand = this.DisplayInCommand,
                FileOption = this.FileOption
            };
        }

        internal GrawlTaskOption FromSerializedGrawlTaskOption(SerializedGrawlTaskOption option)
        {
            this.Name = option.Name;
            this.Value = option.Value;
            this.DefaultValue = option.DefaultValue;
            this.Description = option.Description;
            this.SuggestedValues = option.SuggestedValues;
            this.Optional = option.Optional;
            this.DisplayInCommand = option.DisplayInCommand;
            this.FileOption = option.FileOption;
            return this;
        }

        public string ToYaml()
        {
            ISerializer serializer = new SerializerBuilder().Build();
            return serializer.Serialize(this.ToSerializedGrawlTaskOption());
        }

        public GrawlTaskOption FromYaml(string yaml)
        {
            IDeserializer deserializer = new DeserializerBuilder().Build();
            SerializedGrawlTaskOption option = deserializer.Deserialize<SerializedGrawlTaskOption>(yaml);
            return this.FromSerializedGrawlTaskOption(option);
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this.ToSerializedGrawlTaskOption());
        }

        public GrawlTaskOption FromJson(string json)
        {
            SerializedGrawlTaskOption option = JsonConvert.DeserializeObject<SerializedGrawlTaskOption>(json);
            return this.FromSerializedGrawlTaskOption(option);
        }
    }

    internal class SerializedGrawlTaskOption
    {
        public string Name { get; set; } = "";
        public string Value { get; set; } = "";
        public string DefaultValue { get; set; } = "";
        public string Description { get; set; } = "";
        public List<string> SuggestedValues { get; set; } = new List<string>();
        public bool Optional { get; set; } = false;
        public bool DisplayInCommand { get; set; } = true;
        public bool FileOption { get; set; } = false;
    }
}
