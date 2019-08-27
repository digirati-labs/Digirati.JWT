using System;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Xunit;

namespace Digirati.JWT.Tests
{
    public class X509JsonSignedTokenProviderTests
    {
        private const string CertificateThumbprint = "8e4be666eec44fc972b0a35bed0de94fafa8c982";
        [Fact]
        public void SignArbitrary_CanSign_AnyByteData()
        {
            var provider = X509JsonSignedTokenProvider.LoadByThumbprint(CertificateThumbprint, StoreLocation.LocalMachine);

            var random = new byte[256];
            new Random().NextBytes(random);

            byte[] result = null;
            new Action(()=>result = provider.SignArbitrary(random)).Should().NotThrow();
            result.Should().NotBeNull();
        }
    }
}