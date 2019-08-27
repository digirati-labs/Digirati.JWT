using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using JetBrains.Annotations;
using Microsoft.IdentityModel.Tokens;

namespace Digirati.JWT
{
    [PublicAPI]
    public class X509JsonSignedTokenProvider : JsonSignedTokenProvider
    {
        private readonly X509Certificate2 _certificate;

        public X509JsonSignedTokenProvider(X509Certificate2 certificate) : base(new X509SigningCredentials(certificate, "RS256"))
        {
            _certificate = certificate;
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

        [PublicAPI]
        public byte[] SignArbitrary(byte[] data)
        {
            switch (_certificate.PrivateKey)
            {
                case RSACryptoServiceProvider csp:
                    return csp.SignData(data, GetHashAlgorithm(csp.CspKeyContainerInfo), RSASignaturePadding.Pkcs1);
                case RSACng csp:
                    return csp.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
                default:
                    throw new NotSupportedException($"Not support as of yet for '{_certificate.PrivateKey.GetType().FullName}'");
            }
        }

        private static HashAlgorithmName GetHashAlgorithm(CspKeyContainerInfo containerInfo)
        {
            switch (containerInfo.ProviderName)
            {
                case "Microsoft Enhanced RSA and AES Cryptographic Provider":
                case "Microsoft Base Smart Card Crypto Provider":
                    return HashAlgorithmName.SHA512;

                default:
                    return HashAlgorithmName.SHA1;
            }
        }

        [PublicAPI]
        public bool VerifyArbitrary(byte[] data, byte[] signature)
        {
            switch (_certificate.PrivateKey)
            {
                case RSACryptoServiceProvider csp:
                    return csp.VerifyData(data, signature, GetHashAlgorithm(csp.CspKeyContainerInfo), RSASignaturePadding.Pkcs1);
                case RSACng csp:
                    return csp.VerifyData(data, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
                default:
                    throw new NotSupportedException($"Not support as of yet for '{_certificate.PrivateKey.GetType().FullName}'");
            }
            
        }
    }
}