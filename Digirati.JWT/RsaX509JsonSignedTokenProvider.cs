using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Digirati.JWT
{
    internal class RsaX509JsonSignedTokenProvider : X509JsonSignedTokenProvider
    {
        internal RsaX509JsonSignedTokenProvider(X509Certificate2 certificate) : base(certificate, new X509SigningCredentials(certificate))
        {
        }

        protected override AsymmetricAlgorithm GetPrivateKeyAlgorithm() => Certificate.GetRSAPrivateKey();
    }
}