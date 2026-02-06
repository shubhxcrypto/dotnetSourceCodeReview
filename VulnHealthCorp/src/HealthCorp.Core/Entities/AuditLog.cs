using System;

namespace HealthCorp.Core.Entities;

public class AuditLog
{
    public int Id { get; set; } // Oracle usually uses Number(10), mapped to int
    public string Action { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty; // Not FK, just string
    public string Details { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public string IPAddress { get; set; } = string.Empty;
}
