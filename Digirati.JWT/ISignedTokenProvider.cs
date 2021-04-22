using System;
using System.Collections.Generic;

namespace Digirati.JWT
{
    public interface ISignedTokenProvider : IDisposable
    {
        byte[] SignArbitrary(byte[] data);
        bool VerifyArbitrary(byte[] data, byte[] signature);

        string GetToken(string subject, IEnumerable<(string claim, string value)> claims,
            string issuer = null, string audience = null, DateTime? expiry = null, DateTime? notBefore = null,
            DateTime? issuedAt = null);

        string GetTokenFor(string subject, IEnumerable<(string claim, string value)> claims, TimeSpan expiry,
            string issuer = null, string audience = null, DateTime? notBefore = null,
            DateTime? issuedAt = null);
    }
}