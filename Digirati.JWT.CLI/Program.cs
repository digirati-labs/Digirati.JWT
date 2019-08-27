using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using CommandLine;

namespace Digirati.JWT.CLI
{
    class Program
    {
        public abstract class DefaultOptions
        {
            [Option('e',"expiry",Required = false,Default = "1d",HelpText="Expiry time of the JWT from now")]
            public string ExpiryTime { get; set; }

            [Option('s', "subject", Required=true, HelpText = "Subject of the issued JWT")]
            public string Subject { get; set; }

            [Option('i', "issuer", Required=false, HelpText = "Issuer of the JWT")]
            public string Issuer { get; set; }

            [Option('a', "audience", Required=false, HelpText = "Audience of the issued JWT")]
            public string Audience { get; set; }

            [Option('c', "claim", Separator=',', Required = false, HelpText = "Comma separated list of claims in the form of claimName:claimValue,otherName:otherValue")]
            public IEnumerable<string> Claims { get; set; }

            [Option("saveas", Required=false, HelpText = "Save this call as a profile under provided name")]
            public string SaveAs { get; set; }

            internal string CommandLine { get; set; }
        }
        
        [Verb("profile",HelpText = "Generate JWT from a saved profile")]
        public class ProfileOptions
        {
            [Value(0)]
            public string Name{ get; set; }
        }

        [Verb("cert", HelpText = "Generate JWT from an installed certificate")]
        public class CertificateOptions : DefaultOptions
        {
            [Option('t',"thumb",Required = true,HelpText = "Thumbprint of the certificate to use")]
            public string Thumbprint { get; set; }

            [Option('u', "userstore", Required = false, Default = false, HelpText = "Use current user's certificate store instead of the machine one")]
            public bool UseUserCertStore { get; set; }
        }

        static int Main(string[] args)
        {
            try
            {
                return Parse(args);
            }
            catch (UserErrorException userError)
            {
                Console.Error.WriteLine(userError.Message);
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine(exception.ToString());
            }
            return 1;
        }

        private static int Parse(string[] args)
        {
            return Parser.Default.ParseArguments<ProfileOptions, CertificateOptions>(args)
                .MapResult(
                    (ProfileOptions options) => HandleDispatch(options),
                    (CertificateOptions options) => HandleDispatch(options),
                    errs => 1);
        }

        private static int HandleDispatch<T>(T options)
        {
            if (options is DefaultOptions defaultOptions)
                defaultOptions.CommandLine = Parser.Default.FormatCommandLine(options);

            return Handle((dynamic) options);
        }

        private static int Handle(CertificateOptions options)
            => GenerateToken(options,
                X509JsonSignedTokenProvider.LoadByThumbprint(options.Thumbprint,
                    options.UseUserCertStore ? StoreLocation.CurrentUser : StoreLocation.LocalMachine));

        private static int Handle(ProfileOptions options)
            => LoadProfile(options);

        private static int LoadProfile(ProfileOptions options)
        {
            var fInfo = new FileInfo(Path.Combine(GetProfileDirectory().FullName,  GetProfileFileName(options.Name)));
            if (!fInfo.Exists)
                throw new UserErrorException($"Profile '{options.Name}' not found.");

            var commandLine = File.ReadAllText(fInfo.FullName);
            if (string.IsNullOrWhiteSpace(commandLine))
            {
                fInfo.Delete();
                throw new UserErrorException($"Profile '{options.Name}' not found.");
            }

            return Parse(commandLine.Split(new []{' '}, StringSplitOptions.RemoveEmptyEntries));
        }

        private static int GenerateToken(DefaultOptions options, JsonWebTokenProvider provider)
        {
            // Validate
            if (!TimeParser.TimeParser.TryParseTimeString(options.ExpiryTime, out var expiry))
                throw new UserErrorException($"Cannot parse time string: '{options.ExpiryTime}'");

            var claims = options.Claims.Select(cStr =>
            {
                var parts = cStr.Split(':');
                if (parts.Length != 2)
                    throw new UserErrorException($"Claim '{cStr}' is not in a valid format: 'claimName:claimValue'.");

                return (claim: parts[0], value: parts[1]);
            }).ToArray();


            Console.WriteLine(provider.GetTokenFor(
                options.Subject,
                claims,
                expiry,
                options.Issuer,
                options.Audience
            ));

            if (!string.IsNullOrWhiteSpace(options.SaveAs))
                SaveProfile(options);

            return 0;
        }

        private static void SaveProfile(DefaultOptions options)
        {
            var fInfo = new FileInfo(Path.Combine(GetProfileDirectory().FullName,  GetProfileFileName(options.SaveAs)));
            if (fInfo.Exists)
            {
                while (true)
                {
                    Console.WriteLine($"Profile '{options.SaveAs}' already exists. Overwrite [y/N]?");
                    var decision = Console.ReadKey();

                    if (decision.Key == ConsoleKey.Enter || decision.Key == ConsoleKey.N)
                        return;
                    if (decision.Key == ConsoleKey.Y)
                        break;
                }
            }

            File.WriteAllText(fInfo.FullName, options.CommandLine);
        }

        private static string GetProfileFileName(string profileName)
        {
            var fileName = (Span<char>)(profileName + ".profile").ToCharArray();
            var invalidCharSet = Path.GetInvalidFileNameChars().ToHashSet();
            for(var i = 0; i < fileName.Length; ++i)
                if (invalidCharSet.Contains(fileName[i]))
                    fileName[i] = '_';

            return new string(fileName.ToArray());
        }

        private static DirectoryInfo GetProfileDirectory()
        {
            const string applicationName = "Digirati.JWT.CLI";
            var dInfo = new DirectoryInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), applicationName));
            if(!dInfo.Exists)
                dInfo.Create();

            return dInfo;
        }
    }
}
