using HealthCorp.Core.Entities;
using HealthCorp.Infrastructure.Data;
using HealthCorp.Web.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace HealthCorp.Web.Controllers;

public class AccountController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<AccountController> _logger;

    public AccountController(ApplicationDbContext context, ILogger<AccountController> logger)
    {
        _context = context;
        _logger = logger;
    }

    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        // VULNERABILITY: SQL Injection (Easy)
        // Using raw string concatenation with FromSqlRaw or similar logic.
        // Even worse: constructing the query manually.
        
        try 
        {
            // Simulate legacy check or just bad code
            var query = $"SELECT * FROM USERS WHERE Username = '{model.Username}' AND PasswordHash = '{model.Password}'"; 
            // Note: PasswordHash in model is actually the password input here, treating it as hash for simplicity/vulnerability
            
            // For the sake of standard EF Core 'FromSqlRaw', we need to return entities.
            // This is clearly vulnerable to ' OR '1'='1
            var user = await _context.Users
                .FromSqlRaw($"SELECT * FROM USERS WHERE Username = '{model.Username}' AND PasswordHash = '{model.Password}'")
                .FirstOrDefaultAsync();

            if (user != null)
            {
                await SignInUser(user);
                return RedirectToAction("Index", "Home");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login error");
            ModelState.AddModelError("", "Invalid login attempt."); // Generic message, but logging might expose too much
        }

        ModelState.AddModelError("", "Invalid username or password.");
        return View(model);
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (!ModelState.IsValid) return View(model);

        // Check if user exists (Vulnerable: Race condition possible, though minor here)
        if (await _context.Users.AnyAsync(u => u.Username == model.Username))
        {
            ModelState.AddModelError("", "Username already exists.");
            return View(model);
        }

        var user = new User
        {
            Username = model.Username,
            PasswordHash = model.Password, // VULNERABILITY: Storing plaintext password (labeled 'Hash')
            FullName = model.FullName,
            Email = model.Email,
            Role = "User",
            IsActive = true
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        await SignInUser(user);
        return RedirectToAction("Index", "Home");
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Index", "Home");
    }

    private async Task SignInUser(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim("UserId", user.Id.ToString())
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties();

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);
    }
}
