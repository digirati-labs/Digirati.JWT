using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;

namespace Digirati.JWT
{
    public abstract class JsonSignedTokenProvider : JsonWebTokenProvider
    {
        private readonly SigningCredentials _signingCredentials;

        protected JsonSignedTokenProvider(SigningCredentials signingCredentials)
        {
            _signingCredentials = signingCredentials;
        }

        protected override SecurityTokenDescriptor GetTokenDescriptor(string subject, IEnumerable<(string claim, string value)> claims, string issuer, string audience,
            DateTime? expiry, DateTime? notBefore, DateTime? issuedAt)
        {
            var tokenDescriptor = base.GetTokenDescriptor(subject, claims, issuer, audience, expiry, notBefore, issuedAt);
            tokenDescriptor.SigningCredentials = _signingCredentials;
            return tokenDescriptor;
        }
    }
}