using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.IdentityModel.Tokens;

using System.Security.Claims;
using JetBrains.Annotations;

namespace Digirati.JWT
{
    public abstract class JsonWebTokenProvider
    {
        private SecurityTokenHandler TokenHandler { get; } = new JwtSecurityTokenHandler();

        [PublicAPI]
        public string GetToken(string subject, IEnumerable<(string claim, string value)> claims,
            string issuer = null, string audience = null, DateTime? expiry = null, DateTime? notBefore = null,
            DateTime? issuedAt = null)
            => TokenHandler.WriteToken(
                TokenHandler.CreateToken(
                    GetTokenDescriptor(subject, claims, issuer, audience, expiry, notBefore, issuedAt)
                ));

        [PublicAPI]
        public string GetTokenFor(string subject, IEnumerable<(string claim, string value)> claims, TimeSpan expiry,
            string issuer = null, string audience = null, DateTime? notBefore = null,
            DateTime? issuedAt = null)
            => GetToken(subject, claims, issuer, audience, DateTime.Now.Add(expiry), notBefore, issuedAt);

        protected virtual SecurityTokenDescriptor GetTokenDescriptor(string subject,
            IEnumerable<(string claim, string value)> claims,
            string issuer, string audience, DateTime? expiry, DateTime? notBefore,
            DateTime? issuedAt)
        {
            var identity = new ClaimsIdentity(
                (claims ?? Enumerable.Empty<(string claim, string value)>())
                .Select(pair => new Claim(pair.claim, pair.value)));

            if(subject != null)
                identity.AddClaim(new Claim("sub",subject));

            return new SecurityTokenDescriptor
            {
                Subject = identity,
                Issuer = issuer,
                Audience = audience,
                Expires = expiry,
                IssuedAt = issuedAt,
                NotBefore = notBefore
            };
        }
    }
}
