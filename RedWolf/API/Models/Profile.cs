// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace RedWolf.API.Models
{
    using Newtonsoft.Json;
    using System.Linq;

    public partial class Profile
    {
        /// <summary>
        /// Initializes a new instance of the Profile class.
        /// </summary>
        public Profile()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the Profile class.
        /// </summary>
        /// <param name="type">Possible values include: 'HTTP',
        /// 'Bridge'</param>
        public Profile(int? id = default(int?), string name = default(string), string description = default(string), ProfileType? type = default(ProfileType?), string messageTransform = default(string))
        {
            Id = id;
            Name = name;
            Description = description;
            Type = type;
            MessageTransform = messageTransform;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "id")]
        public int? Id { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "name")]
        public string Name { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "description")]
        public string Description { get; set; }

        /// <summary>
        /// Gets or sets possible values include: 'HTTP', 'Bridge'
        /// </summary>
        [JsonProperty(PropertyName = "type")]
        public ProfileType? Type { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "messageTransform")]
        public string MessageTransform { get; set; }

    }
}