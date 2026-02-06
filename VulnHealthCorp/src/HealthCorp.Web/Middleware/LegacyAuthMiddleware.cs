using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace HealthCorp.Web.Middleware;

// VULNERABILTY: Custom auth middleware that looks specifically for a "LegacyAuth" header 
// or a specific cookie, bypassing standard ASP.NET Identity controls if present.
public class LegacyAuthMiddleware
{
    private readonly RequestDelegate _next;

    public LegacyAuthMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Easy Auth Bypass: Check for a header "X-HealthCorp-Admin"
        if (context.Request.Headers.ContainsKey("X-HealthCorp-Admin"))
        {
            var adminUser = new ClaimsPrincipal(new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, "LegacyAdmin"),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim("IsLegacy", "true")
            }, "LegacyApiKey"));

            context.User = adminUser;
        }
        else if (context.Request.Cookies.ContainsKey("HC_User"))
        {
            // Easy Logic: Trusting cookie value directly? 
            // Maybe just parsing it simply without verifying signature (Simulated insecure deserialization or just trust)
            var userVal = context.Request.Cookies["HC_User"];
            if (!string.IsNullOrEmpty(userVal))
            {
                // Assuming format "username|role"
                var parts = userVal.Split('|');
                if (parts.Length == 2)
                {
                    var user = new ClaimsPrincipal(new ClaimsIdentity(new[]
                    {
                        new Claim(ClaimTypes.Name, parts[0]),
                        new Claim(ClaimTypes.Role, parts[1])
                    }, "LegacyCookie"));
                    context.User = user;
                }
            }
        }

        await _next(context);
    }
}
