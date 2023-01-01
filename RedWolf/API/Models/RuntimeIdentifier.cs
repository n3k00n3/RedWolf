// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace RedWolf.API.Models
{
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;
    using System.Runtime;
    using System.Runtime.Serialization;

    /// <summary>
    /// Defines values for RuntimeIdentifier.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum RuntimeIdentifier
    {
        [EnumMember(Value = "win_x64")]
        WinX64,
        [EnumMember(Value = "win_x86")]
        WinX86,
        [EnumMember(Value = "win_arm")]
        WinArm,
        [EnumMember(Value = "win_arm64")]
        WinArm64,
        [EnumMember(Value = "win7_x64")]
        Win7X64,
        [EnumMember(Value = "win7_x86")]
        Win7X86,
        [EnumMember(Value = "win81_x64")]
        Win81X64,
        [EnumMember(Value = "win81_x86")]
        Win81X86,
        [EnumMember(Value = "win81_arm")]
        Win81Arm,
        [EnumMember(Value = "win10_x64")]
        Win10X64,
        [EnumMember(Value = "win10_x86")]
        Win10X86,
        [EnumMember(Value = "win10_arm")]
        Win10Arm,
        [EnumMember(Value = "win10_arm64")]
        Win10Arm64,
        [EnumMember(Value = "linux_x64")]
        LinuxX64,
        [EnumMember(Value = "linux_musl_x64")]
        LinuxMuslX64,
        [EnumMember(Value = "linux_arm")]
        LinuxArm,
        [EnumMember(Value = "linux_arm64")]
        LinuxArm64,
        [EnumMember(Value = "rhel_x64")]
        RhelX64,
        [EnumMember(Value = "rhel_6_x64")]
        Rhel6X64,
        [EnumMember(Value = "tizen")]
        Tizen,
        [EnumMember(Value = "tizen_4_0_0")]
        Tizen400,
        [EnumMember(Value = "tizen_5_0_0")]
        Tizen500,
        [EnumMember(Value = "osx_x64")]
        OsxX64,
        [EnumMember(Value = "osx_10_10_x64")]
        Osx1010X64,
        [EnumMember(Value = "osx_10_11_x64")]
        Osx1011X64,
        [EnumMember(Value = "osx_10_12_x64")]
        Osx1012X64,
        [EnumMember(Value = "osx_10_13_x64")]
        Osx1013X64,
        [EnumMember(Value = "osx_10_14_x64")]
        Osx1014X64,
        [EnumMember(Value = "osx_10_15_x64")]
        Osx1015X64
    }
    internal static class RuntimeIdentifierEnumExtension
    {
        internal static string ToSerializedValue(this RuntimeIdentifier? value)
        {
            return value == null ? null : ((RuntimeIdentifier)value).ToSerializedValue();
        }

        internal static string ToSerializedValue(this RuntimeIdentifier value)
        {
            switch( value )
            {
                case RuntimeIdentifier.WinX64:
                    return "win_x64";
                case RuntimeIdentifier.WinX86:
                    return "win_x86";
                case RuntimeIdentifier.WinArm:
                    return "win_arm";
                case RuntimeIdentifier.WinArm64:
                    return "win_arm64";
                case RuntimeIdentifier.Win7X64:
                    return "win7_x64";
                case RuntimeIdentifier.Win7X86:
                    return "win7_x86";
                case RuntimeIdentifier.Win81X64:
                    return "win81_x64";
                case RuntimeIdentifier.Win81X86:
                    return "win81_x86";
                case RuntimeIdentifier.Win81Arm:
                    return "win81_arm";
                case RuntimeIdentifier.Win10X64:
                    return "win10_x64";
                case RuntimeIdentifier.Win10X86:
                    return "win10_x86";
                case RuntimeIdentifier.Win10Arm:
                    return "win10_arm";
                case RuntimeIdentifier.Win10Arm64:
                    return "win10_arm64";
                case RuntimeIdentifier.LinuxX64:
                    return "linux_x64";
                case RuntimeIdentifier.LinuxMuslX64:
                    return "linux_musl_x64";
                case RuntimeIdentifier.LinuxArm:
                    return "linux_arm";
                case RuntimeIdentifier.LinuxArm64:
                    return "linux_arm64";
                case RuntimeIdentifier.RhelX64:
                    return "rhel_x64";
                case RuntimeIdentifier.Rhel6X64:
                    return "rhel_6_x64";
                case RuntimeIdentifier.Tizen:
                    return "tizen";
                case RuntimeIdentifier.Tizen400:
                    return "tizen_4_0_0";
                case RuntimeIdentifier.Tizen500:
                    return "tizen_5_0_0";
                case RuntimeIdentifier.OsxX64:
                    return "osx_x64";
                case RuntimeIdentifier.Osx1010X64:
                    return "osx_10_10_x64";
                case RuntimeIdentifier.Osx1011X64:
                    return "osx_10_11_x64";
                case RuntimeIdentifier.Osx1012X64:
                    return "osx_10_12_x64";
                case RuntimeIdentifier.Osx1013X64:
                    return "osx_10_13_x64";
                case RuntimeIdentifier.Osx1014X64:
                    return "osx_10_14_x64";
                case RuntimeIdentifier.Osx1015X64:
                    return "osx_10_15_x64";
            }
            return null;
        }

        internal static RuntimeIdentifier? ParseRuntimeIdentifier(this string value)
        {
            switch( value )
            {
                case "win_x64":
                    return RuntimeIdentifier.WinX64;
                case "win_x86":
                    return RuntimeIdentifier.WinX86;
                case "win_arm":
                    return RuntimeIdentifier.WinArm;
                case "win_arm64":
                    return RuntimeIdentifier.WinArm64;
                case "win7_x64":
                    return RuntimeIdentifier.Win7X64;
                case "win7_x86":
                    return RuntimeIdentifier.Win7X86;
                case "win81_x64":
                    return RuntimeIdentifier.Win81X64;
                case "win81_x86":
                    return RuntimeIdentifier.Win81X86;
                case "win81_arm":
                    return RuntimeIdentifier.Win81Arm;
                case "win10_x64":
                    return RuntimeIdentifier.Win10X64;
                case "win10_x86":
                    return RuntimeIdentifier.Win10X86;
                case "win10_arm":
                    return RuntimeIdentifier.Win10Arm;
                case "win10_arm64":
                    return RuntimeIdentifier.Win10Arm64;
                case "linux_x64":
                    return RuntimeIdentifier.LinuxX64;
                case "linux_musl_x64":
                    return RuntimeIdentifier.LinuxMuslX64;
                case "linux_arm":
                    return RuntimeIdentifier.LinuxArm;
                case "linux_arm64":
                    return RuntimeIdentifier.LinuxArm64;
                case "rhel_x64":
                    return RuntimeIdentifier.RhelX64;
                case "rhel_6_x64":
                    return RuntimeIdentifier.Rhel6X64;
                case "tizen":
                    return RuntimeIdentifier.Tizen;
                case "tizen_4_0_0":
                    return RuntimeIdentifier.Tizen400;
                case "tizen_5_0_0":
                    return RuntimeIdentifier.Tizen500;
                case "osx_x64":
                    return RuntimeIdentifier.OsxX64;
                case "osx_10_10_x64":
                    return RuntimeIdentifier.Osx1010X64;
                case "osx_10_11_x64":
                    return RuntimeIdentifier.Osx1011X64;
                case "osx_10_12_x64":
                    return RuntimeIdentifier.Osx1012X64;
                case "osx_10_13_x64":
                    return RuntimeIdentifier.Osx1013X64;
                case "osx_10_14_x64":
                    return RuntimeIdentifier.Osx1014X64;
                case "osx_10_15_x64":
                    return RuntimeIdentifier.Osx1015X64;
            }
            return null;
        }
    }
}