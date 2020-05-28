using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace Digirati.JWT.Tests
{
    public class X509JsonSignedTokenProviderTests
    {
        private  const string CertificateName = "Digirati_JWT_Test_Cert";
        private readonly ITestOutputHelper _helper;

        public X509JsonSignedTokenProviderTests(ITestOutputHelper helper)
        {
            _helper = helper;
        }

        [Theory]
        [MemberData(nameof(GetThumbprints))]
        public void SignArbitrary_CanSign_AnyByteData(string thumbprint)
        {
            using (var provider = X509JsonSignedTokenProvider.LoadByThumbprint(thumbprint, StoreLocation.CurrentUser))
            {

                var random = new byte[256];
                new Random().NextBytes(random);

                byte[] result = null;
                new Action(() => result = provider.SignArbitrary(random)).Should().NotThrow();
                result.Should().NotBeNull();
            }
        }

        [Theory]
        [MemberData(nameof(GetThumbprints))]
        public void GetToken_Should_NotThrow(string thumbprint)
        {

            using (var provider = X509JsonSignedTokenProvider.LoadByThumbprint(thumbprint, StoreLocation.CurrentUser))
            {
                var random = new byte[256];
                new Random().NextBytes(random);

                string result = null;
                new Action(() => result = provider.GetToken("subject", Enumerable.Empty<(string claim, string value)>(), "issuer", "audience")).Should().NotThrow();
            }
        }

        public static IEnumerable<object[]> GetThumbprints()
        {
            var fromFile = GetThumbprintsFromFile().ToList();
            if (fromFile.Any()) return fromFile;

            // No predefined thumbprints, generate a test certificate
            return GetThumbprintsGenerated();
        }

        private static IEnumerable<object[]> GetThumbprintsGenerated()
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddIpAddress(IPAddress.Loopback);
            sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddDnsName(Environment.MachineName);

            var distinguishedName = new X500DistinguishedName($"CN={CertificateName}");
            X509Certificate2 newCert;
            using (var rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));


                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

                request.CertificateExtensions.Add(sanBuilder.Build());

                var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));

                newCert =  new X509Certificate2(certificate.Export(X509ContentType.Pfx, "WeNeedASaf3rPassword"), "WeNeedASaf3rPassword", X509KeyStorageFlags.MachineKeySet);
            }

            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser, OpenFlags.ReadWrite))
            {
                store.Add(newCert);
            }

            yield return new object[]{ newCert.Thumbprint };
        }

        public static IEnumerable<object[]> GetThumbprintsFromFile()
        {
            var resourceName = $"{typeof(X509JsonSignedTokenProviderTests).Assembly.GetName().Name}.thumbprints.txt";
            using (var stream = typeof(X509JsonSignedTokenProviderTests).Assembly.GetManifestResourceStream(resourceName))
            using (var reader = new StreamReader(stream))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                    yield return new object[] {line};


            }
        }
    }
}