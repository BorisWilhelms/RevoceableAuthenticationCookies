using System;

namespace RevoceableAuthenticationCookies.Models
{
    public class AuthenticationCookie
    {
        public AuthenticationCookie()
        {

        }

        public AuthenticationCookie(string userId, Guid id, DateTimeOffset expires)
        {
            UserId = userId;
            Id = id;
            Expires = expires;
        }

        public string UserId { get; set; }

        public Guid Id { get; set; }

        public DateTimeOffset Expires { get; set; }
    }
}
