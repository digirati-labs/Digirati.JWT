using System;
using System.Security.Cryptography.X509Certificates;
using JetBrains.Annotations;
using Microsoft.IdentityModel.Tokens;

namespace Digirati.JWT
{
    [PublicAPI]
    public class X509JsonSignedTokenProvider : JsonSignedTokenProvider
    {
        public X509JsonSignedTokenProvider(X509Certificate2 certificate) : base(new X509SigningCredentials(certificate, "RS256"))
        {
        }

        [PublicAPI]
        public static X509JsonSignedTokenProvider LoadByThumbprint([NotNull] string thumbprint,
            StoreLocation storeLocation)
        {
            
            X509Certificate2 cert;
            using(var store = new X509Store(storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

                switch (certs.Count)
                {
                    case 0: 
                        throw new ArgumentException($"Cannot find certificate with thumbprint '{thumbprint}' in the {store.Name} store");

                    case 1: cert = certs[0];
                        break;

                    default:
                        throw new ArgumentException($"Found more than one certificate with thumbprint '{thumbprint}' in the {store.Name} store");
                }
            }

            if (!cert.HasPrivateKey)
                throw new ArgumentException(
                    $"Certificate with thumbprint '{thumbprint}' does not have private key attached.");

            return new X509JsonSignedTokenProvider(cert);
        }
    }
}