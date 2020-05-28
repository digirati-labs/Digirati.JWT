using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using JetBrains.Annotations;
using Microsoft.IdentityModel.Tokens;

namespace Digirati.JWT
{
    public abstract class X509JsonSignedTokenProvider : JsonSignedTokenProvider, IDisposable
    {
        protected readonly X509Certificate2 Certificate;

        protected X509JsonSignedTokenProvider(X509Certificate2 certificate, SigningCredentials credentials) : base(credentials)
        {
            Certificate = certificate;
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

            return Create(cert);
        }

        [PublicAPI]
        public static X509JsonSignedTokenProvider Create(X509Certificate2 cert)
        {
            if(cert.GetRSAPrivateKey() != null)
                return new RsaX509JsonSignedTokenProvider(cert);
            if(cert.GetECDsaPrivateKey() != null)
                return new EcdsaX509JsonSignedTokenProvider(cert);

            throw new NotSupportedException("Only RSA and ECDSA are supported.");
        }

        [PublicAPI]
        public byte[] SignArbitrary(byte[] data)
        {
            var asymmetricAlgorithm = GetPrivateKeyAlgorithm();
            switch (asymmetricAlgorithm)
            {
                case null:
                    throw new ArgumentException($"Cannot obtain the {nameof(AsymmetricAlgorithm)} from the certificate using {nameof(GetPrivateKeyAlgorithm)} implementation of {GetType().FullName} class");
                case RSACryptoServiceProvider csp:
                    return csp.SignData(data, GetHashAlgorithm(csp.CspKeyContainerInfo), RSASignaturePadding.Pkcs1);
                case RSACng csp:
                    return csp.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
                case ECDsa csp:
                    return csp.SignData(data, HashAlgorithmName.SHA512);
                case RSA rsa:
                    return rsa.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
                default:
                    throw new NotSupportedException($"Not support as of yet for '{asymmetricAlgorithm.GetType().FullName}'");
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

        protected abstract AsymmetricAlgorithm GetPrivateKeyAlgorithm();

        [PublicAPI]
        public bool VerifyArbitrary(byte[] data, byte[] signature)
        {
            var asymmetricAlgorithm = GetPrivateKeyAlgorithm();
            switch (asymmetricAlgorithm)
            {
                case null:
                    throw new ArgumentException($"Cannot obtain the {nameof(AsymmetricAlgorithm)} from the certificate using {nameof(GetPrivateKeyAlgorithm)} implementation of {GetType().FullName} class");
                case RSACryptoServiceProvider csp:
                    return csp.VerifyData(data, signature, GetHashAlgorithm(csp.CspKeyContainerInfo), RSASignaturePadding.Pkcs1);
                case RSACng csp:
                    return csp.VerifyData(data, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
                case ECDsa csp:
                    return csp.VerifyData(data, signature, HashAlgorithmName.SHA512);
                default:
                    throw new NotSupportedException($"Not support as of yet for '{asymmetricAlgorithm.GetType().FullName}'");
            }
            
        }

        public void Dispose()
        {
            Certificate?.Dispose();
        }
    }
}