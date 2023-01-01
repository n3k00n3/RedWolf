using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

using Microsoft.CodeAnalysis;

using Newtonsoft.Json;
using YamlDotNet.Serialization;

using RedWolf.Core;

namespace RedWolf.Models.Grawls
{
    public class GrawlTaskAuthor : ISerializable<GrawlTaskAuthor>
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string Handle { get; set; } = "";
        public string Link { get; set; } = "";

        public List<GrawlTask> GrawlTasks { get; set; }

        internal SerializedGrawlTaskAuthor ToSerializedGrawlTaskAuthor()
        {
            return new SerializedGrawlTaskAuthor
            {
                Name = this.Name,
                Handle = this.Handle,
                Link = this.Link
            };
        }

        internal GrawlTaskAuthor FromSerializedGrawlTaskAuthor(SerializedGrawlTaskAuthor author)
        {
            this.Name = author.Name;
            this.Handle = author.Handle;
            this.Link = author.Link;
            return this;
        }

        public string ToYaml()
        {
            ISerializer serializer = new SerializerBuilder().Build();
            return serializer.Serialize(this.ToSerializedGrawlTaskAuthor());
        }

        public GrawlTaskAuthor FromYaml(string yaml)
        {
            IDeserializer deserializer = new DeserializerBuilder().Build();
            SerializedGrawlTaskAuthor author = deserializer.Deserialize<SerializedGrawlTaskAuthor>(yaml);
            return this.FromSerializedGrawlTaskAuthor(author);
        }

        public string ToJson()
        {
            return JsonConvert.SerializeObject(this.ToSerializedGrawlTaskAuthor());
        }

        public GrawlTaskAuthor FromJson(string json)
        {
            SerializedGrawlTaskAuthor author = JsonConvert.DeserializeObject<SerializedGrawlTaskAuthor>(json);
            return this.FromSerializedGrawlTaskAuthor(author);
        }
    }

    internal class SerializedGrawlTaskAuthor
    {
        public string Name { get; set; } = "";
        public string Handle { get; set; } = "";
        public string Link { get; set; } = "";
    }
}
