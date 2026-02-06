using HealthCorp.Core.Entities;
using HealthCorp.Core.Interfaces;
using HealthCorp.Infrastructure.Data;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace HealthCorp.Infrastructure.Services;

public class AuditService : IAuditService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<AuditService> _logger;

    public AuditService(ApplicationDbContext context, ILogger<AuditService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task LogAsync(string action, string username, string details)
    {
        var log = new AuditLog
        {
            Action = action,
            Username = username,
            Details = details,
            IPAddress = "127.0.0.1" // Hardcoded for now
        };

        _context.AuditLogs.Add(log);
        await _context.SaveChangesAsync();
        
        _logger.LogInformation($"Audit: {action} by {username}");
    }

    public async Task LogSensitiveAsync(string action, string username, object sensitiveData)
    {
        // VULNERABILITY: Logging sensitive object structure directly to text logs/console
        // This is a "Logging & monitoring failure"
        var paramsJson = JsonSerializer.Serialize(sensitiveData);
        _logger.LogWarning($"[SENSITIVE_AUDIT] {action} by {username} with data: {paramsJson}");

        await LogAsync(action, username, "Sensitive operation performed");
    }
}
