using HealthCorp.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
// Potentially needed for UseOracle extension verification
using Oracle.EntityFrameworkCore; 

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Add Oracle DbContext
builder.Services.AddDbContext<HealthCorp.Infrastructure.Data.ApplicationDbContext>(options =>
    options.UseOracle(builder.Configuration.GetConnectionString("DefaultConnection")));

// Add Services
builder.Services.AddScoped<HealthCorp.Core.Interfaces.IAuditService, HealthCorp.Infrastructure.Services.AuditService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

// VULNERABLE MIDDLEWARE: Legacy Auth before standard Auth
app.UseMiddleware<HealthCorp.Web.Middleware.LegacyAuthMiddleware>();

app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();


app.Run();
