using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Digirati.JWT
{
    internal class EcdsaX509JsonSignedTokenProvider : X509JsonSignedTokenProvider
    {
        internal EcdsaX509JsonSignedTokenProvider(X509Certificate2 certificate) : base(certificate,
            new SigningCredentials(new ECDsaSecurityKey(certificate.GetECDsaPrivateKey()),
                SecurityAlgorithms.EcdsaSha256))
        {
        }

        protected override AsymmetricAlgorithm GetPrivateKeyAlgorithm()
        {
            return Certificate.GetECDsaPrivateKey();
        }
    }
}