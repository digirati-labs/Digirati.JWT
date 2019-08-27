using System;

namespace Digirati.JWT.CLI
{
    public class UserErrorException : Exception
    {
        public UserErrorException(string message) : base(message)
        {
        }
    }
}