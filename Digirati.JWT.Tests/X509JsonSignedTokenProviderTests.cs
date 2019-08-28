using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Xunit;

namespace Digirati.JWT.Tests
{
    public class X509JsonSignedTokenProviderTests
    {
        [Theory]
        [MemberData(nameof(GetThumbprints))]
        public void SignArbitrary_CanSign_AnyByteData(string thumbprint)
        {
            using (var provider = X509JsonSignedTokenProvider.LoadByThumbprint(thumbprint, StoreLocation.LocalMachine))
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

            using (var provider = X509JsonSignedTokenProvider.LoadByThumbprint(thumbprint, StoreLocation.LocalMachine))
            {
                var random = new byte[256];
                new Random().NextBytes(random);

                string result = null;
                new Action(() => result = provider.GetToken("subject", Enumerable.Empty<(string claim, string value)>(), "issuer", "audience")).Should().NotThrow();
            }
        }

        public static IEnumerable<object[]> GetThumbprints()
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