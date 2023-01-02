// Author: Ryan Cobb (@cobbr_io)
// Project: RedWolf (https://github.com/cobbr/RedWolf)
// License: GNU GPLv3

using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;

using NLog.Web;
using NLog.Config;
using NLog.Targets;
using McMaster.Extensions.CommandLineUtils;

using RedWolf.Models;
using RedWolf.Core;
using RedWolf.Models.RedWolf;

namespace RedWolf
{
    public class Program
    {
        static void Main(string[] args)
        {
            CommandLineApplication app = new CommandLineApplication();
            app.HelpOption("-? | -h | --help");

            var UserNameOption = app.Option(
                "-u | --username <USERNAME>",
                "The initial user UserName to create on launch. (env: REDWOLF_USERNAME)",
                CommandOptionType.SingleValue
            );
            var PasswordOption = app.Option(
                "-p | --password <PASSWORD>",
                "The initial user Password to create on launch. (env: REDWOLF_PASSWORD)",
                CommandOptionType.SingleValue
            );
            var ComputerNameOption = app.Option(
                "-c | --computername <COMPUTERNAME>",
                "The ComputerName (IPAddress or Hostname) to bind RedWolf to. (env: REDWOLF_COMPUTER_NAME)",
                CommandOptionType.SingleValue
            );
            var AdminPortOption = app.Option(
                "-a | --adminport <PORT>",
                "The Port number to bind RedWolf to. (env: REDWOLF_PORT)",
                CommandOptionType.SingleValue
            );

            app.OnExecute(() =>
            {
                if (!File.Exists(Path.Combine(Common.RedWolfSharpSploitDirectory, "SharpSploit.sln")) ||
                    !File.Exists(Path.Combine(Common.RedWolfRubeusDirectory, "Rubeus.sln")))
                {
                    Console.Error.WriteLine("Error: git submodules have not been initialized");
                    Console.Error.WriteLine("RedWolf's submodules can be cloned with: git clone --recurse-submodules https://github.com/cobbr/RedWolf");
                    Console.Error.WriteLine("Or initialized after cloning with: git submodule update --init --recursive");
                    return -1;
                }

                string username = UserNameOption.HasValue() ? UserNameOption.Value() : Environment.GetEnvironmentVariable("REDWOLF_USERNAME");
                string password = PasswordOption.HasValue() ? PasswordOption.Value() : Environment.GetEnvironmentVariable("REDWOLF_PASSWORD");
                if (!string.IsNullOrEmpty(username) && string.IsNullOrEmpty(password))
                {
                    Console.Write("Password: ");
                    password = GetPassword();
                    Console.WriteLine();
                }

                string RedWolfBindUrl = ComputerNameOption.HasValue() ? ComputerNameOption.Value() : Environment.GetEnvironmentVariable("REDWOLF_COMPUTER_NAME"); ;
                if (string.IsNullOrEmpty(RedWolfBindUrl))
                {
                    RedWolfBindUrl = "0.0.0.0";
                }

                int RedWolfPort = Common.RedWolfDefaultAdminPort;
                string sPort = AdminPortOption.HasValue() ? AdminPortOption.Value() : Environment.GetEnvironmentVariable("REDWOLF_PORT");
                if (!string.IsNullOrEmpty(sPort) && !int.TryParse(sPort, out RedWolfPort))
                {
                    RedWolfPort = Common.RedWolfDefaultAdminPort;
                }

                IPAddress address = null;
                try
                {
                    address = IPAddress.Parse(RedWolfBindUrl);
                }
                catch (FormatException)
                {
                    address = Dns.GetHostAddresses(RedWolfBindUrl).FirstOrDefault();
                }
                IPEndPoint RedWolfEndpoint = new IPEndPoint(address, RedWolfPort);
                string RedWolfUri = RedWolfBindUrl == "0.0.0.0" ? "https://127.0.0.1:" + RedWolfPort : "https://" + RedWolfEndpoint;
                var host = BuildHost(RedWolfEndpoint, RedWolfUri);
                using (var scope = host.Services.CreateScope())
                {
                    var services = scope.ServiceProvider;
                    var context = services.GetRequiredService<RedWolfContext>();
                    var service = services.GetRequiredService<IRedWolfService>();
                    var userManager = services.GetRequiredService<UserManager<RedWolfUser>>();
                    var signInManager = services.GetRequiredService<SignInManager<RedWolfUser>>();
                    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
                    var configuration = services.GetRequiredService<IConfiguration>();
                    configuration["RedWolfPort"] = RedWolfPort.ToString();
                    var listenerTokenSources = services.GetRequiredService<ConcurrentDictionary<int, CancellationTokenSource>>();
                    context.Database.EnsureCreated();
                    DbInitializer.Initialize(service, context, roleManager, listenerTokenSources).Wait();
                    RedWolfUser serviceUser = new RedWolfUser { UserName = "ServiceUser" };
                    if (!context.Users.Any())
                    {
                        string serviceUserPassword = Utilities.CreateSecretPassword() + "A";
                        userManager.CreateAsync(serviceUser, serviceUserPassword).Wait();
                        userManager.AddToRoleAsync(serviceUser, "ServiceUser").Wait();
                        if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                        {
                            RedWolfUser user = new RedWolfUser { UserName = username };
                            Task<IdentityResult> task = userManager.CreateAsync(user, password);
                            task.Wait();
                            IdentityResult userResult = task.Result;
                            if (userResult.Succeeded)
                            {
                                userManager.AddToRoleAsync(user, "User").Wait();
                                userManager.AddToRoleAsync(user, "Administrator").Wait();
                            }
                            else
                            {
                                Console.Error.WriteLine($"Error creating user: {user.UserName}");
                                return -1;
                            }
                        }
                    }
                    configuration["ServiceUserToken"] = Utilities.GenerateJwtToken(
                        serviceUser.UserName, serviceUser.Id, new string[] { "ServiceUser" },
                        configuration["JwtKey"], configuration["JwtIssuer"],
                        configuration["JwtAudience"], configuration["JwtExpireDays"]
                    );
                }

                LoggingConfiguration loggingConfig = new LoggingConfiguration();
                var consoleTarget = new ColoredConsoleTarget();
                var fileTarget = new FileTarget();
                loggingConfig.AddTarget("console", consoleTarget);
                loggingConfig.AddTarget("file", fileTarget);
                consoleTarget.Layout = @"${longdate}|${event-properties:item=EventId_Id}|${uppercase:${level}}|${logger}|${message} ${exception:format=tostring}";
                fileTarget.Layout = @"${longdate}|${event-properties:item=EventId_Id}|${uppercase:${level}}|${logger}|${message} ${exception:format=tostring}";
                fileTarget.FileName = Common.RedWolfLogDirectory + "covenant.log";
                loggingConfig.AddRule(NLog.LogLevel.Info, NLog.LogLevel.Fatal, "console");
                loggingConfig.AddRule(NLog.LogLevel.Info, NLog.LogLevel.Fatal, "file");

                var logger = NLogBuilder.ConfigureNLog(loggingConfig).GetCurrentClassLogger();
                try
                {
                    logger.Debug("Starting RedWolf API");
                    if (!IsElevated())
                    {
                        Console.Error.WriteLine("WARNING: Running RedWolf non-elevated. You may not have permission to start Listeners on low-numbered ports. Consider running RedWolf elevated.");
                    }
                    Console.WriteLine($"RedWolf has started! Navigate to {RedWolfUri} in a browser");
                    host.Run();
                }
                catch (Exception ex)
                {
                    logger.Error(ex, "RedWolf stopped due to exception");
                    throw;
                }
                finally
                {
                    NLog.LogManager.Shutdown();
                }
                return 0;
            });
            app.Execute(args);
        }

        public static IHost BuildHost(IPEndPoint RedWolfEndpoint, string RedWolfUri) =>
            new HostBuilder()
            .ConfigureWebHost(weboptions =>
            {
                weboptions.UseKestrel(options =>
                {
                    options.Listen(RedWolfEndpoint, listenOptions =>
                    {
                        listenOptions.UseHttps(httpsOptions =>
                        {
                            if (!File.Exists(Common.RedWolfPrivateCertFile) || !File.Exists(Common.RedWolfPublicCertFile))
                            {
                                Console.WriteLine("Creating cert...");
                                X509Certificate2 certificate = Utilities.CreateSelfSignedCertificate(RedWolfEndpoint.Address, "CN=RedWolf");
                                File.WriteAllBytes(Common.RedWolfPrivateCertFile, certificate.Export(X509ContentType.Pfx));
                                File.WriteAllBytes(Common.RedWolfPublicCertFile, certificate.Export(X509ContentType.Cert));
                            }
                            try
                            {
                                httpsOptions.ServerCertificate = new X509Certificate2(Common.RedWolfPrivateCertFile);
                            }
                            catch (CryptographicException)
                            {
                                Console.Error.WriteLine("Error importing RedWolf certificate.");
                            }
                            httpsOptions.SslProtocols = SslProtocols.Tls12;
                        });
                    });
                    // options.Limits.MaxRequestBodySize = int.MaxValue;
                })
                .UseContentRoot(Directory.GetCurrentDirectory())
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    string appsettingscontents = File.ReadAllText(Common.RedWolfAppSettingsFile);
                    if (appsettingscontents.Contains(Common.RedWolfJwtKeyReplaceMessage))
                    {
                        Console.WriteLine("Found default JwtKey, replacing with auto-generated key...");
                        File.WriteAllText(Common.RedWolfAppSettingsFile, appsettingscontents.Replace(Common.RedWolfJwtKeyReplaceMessage, Utilities.GenerateJwtKey()));
                    }
                    var env = hostingContext.HostingEnvironment;
                    config.AddJsonFile(Common.RedWolfAppSettingsFile, optional: false, reloadOnChange: false);
                    config.AddEnvironmentVariables();
                })
                .ConfigureLogging((hostingContext, logging) =>
                {
                    logging.ClearProviders();
                    logging.AddConfiguration(hostingContext.Configuration.GetSection("Logging"));
                    logging.AddConsole();
                    logging.AddDebug();
                    logging.AddFilter("System", LogLevel.Warning)
                           .AddFilter("Microsoft", LogLevel.Warning);
                })
                .UseStartup<Startup>()
                .UseSetting("RedWolfUri", RedWolfUri)
                .UseSetting(WebHostDefaults.DetailedErrorsKey, "true");
            })
            .Build();

        private static bool IsElevated()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole("Administrators");
            }
            return Environment.UserName.Equals("root", StringComparison.CurrentCultureIgnoreCase);
        }

        private static string GetPassword()
        {
            string password = "";
            ConsoleKeyInfo nextKey = Console.ReadKey(true);
            while (nextKey.Key != ConsoleKey.Enter)
            {
                if (nextKey.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password = password.Substring(0, password.Length - 1);
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    password += nextKey.KeyChar;
                    Console.Write("*");
                }
                nextKey = Console.ReadKey(true);
            }
            return password;
        }
    }
}
