using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RevoceableAuthenticationCookies.Data;
using RevoceableAuthenticationCookies.Models;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace RevoceableAuthenticationCookies
{
    public class RevocableCookieAuthenticationOptions : IPostConfigureOptions<CookieAuthenticationOptions>
    {
        private const string TOKEN_NAME = "cookieid";

        public void PostConfigure(string name, CookieAuthenticationOptions options)
        {
            options.Events.OnSigningIn = OnSigningIn;
            options.Events.OnSigningOut = OnSigningOut;
            options.Events.OnValidatePrincipal = OnValidatePrincipal;
        }

        private async Task OnSigningIn(CookieSigningInContext context)
        {
            if (!string.IsNullOrWhiteSpace(context.Properties.GetTokenValue(TOKEN_NAME)))
            {
                return;
            }

            var userId = GetUserId(context.Principal);
            var cookieId = Guid.NewGuid();
            var cookie = new AuthenticationCookie(userId, cookieId, context.Properties.ExpiresUtc.Value);

            var db = context.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();
            await db.AuthenticationCookies.AddAsync(cookie);
            await db.SaveChangesAsync();

            context.Properties.StoreTokens(new[] { new AuthenticationToken() { Name = TOKEN_NAME, Value = cookieId.ToString() } });
        }

        private async Task OnSigningOut(CookieSigningOutContext context)
        {
            var cookieIdValue = await context.HttpContext.GetTokenAsync(TOKEN_NAME);
            if (string.IsNullOrWhiteSpace(cookieIdValue) || !Guid.TryParse(cookieIdValue, out var cookieId))
            {
                return;
            }

            var userId = GetUserId(context.HttpContext.User);

            var db = context.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();
            var entity = await db.AuthenticationCookies.FirstOrDefaultAsync(c => c.UserId == userId && c.Id == cookieId);
            if (entity != null)
            {
                db.AuthenticationCookies.Remove(entity);
                await db.SaveChangesAsync();
            }
        }

        private async Task OnValidatePrincipal(CookieValidatePrincipalContext context)
        {
            var cookieIdValue = context.Properties.GetTokenValue(TOKEN_NAME);
            if (string.IsNullOrWhiteSpace(cookieIdValue) || !Guid.TryParse(cookieIdValue, out var cookieId))
            {
                // Reject authentication cookies that have no token.
                context.RejectPrincipal();
                return;
            }

            var userId = GetUserId(context.Principal);

            var db = context.HttpContext.RequestServices.GetRequiredService<ApplicationDbContext>();
            var entity = await db.AuthenticationCookies.FirstOrDefaultAsync(c => c.UserId == userId && c.Id == cookieId);
            if (entity == null || entity.Expires < DateTimeOffset.UtcNow)
            {
                // Reject authentication cookies that have expired or non existing tokens
                context.RejectPrincipal();
                return;
            }
        }

        private string GetUserId(ClaimsPrincipal principal)
            => principal.FindFirstValue(ClaimTypes.NameIdentifier);
    }
}
