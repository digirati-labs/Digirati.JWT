using JetBrains.Annotations;
using Microsoft.IdentityModel.Tokens;

namespace Digirati.JWT
{
    [PublicAPI]
    public class SecurityKeyJsonSignedTokenProvider : JsonSignedTokenProvider
    {
        protected SecurityKeyJsonSignedTokenProvider(SecurityKey securityKey) : base(new SigningCredentials(securityKey,"RS256"))
        {
        }
    }
}