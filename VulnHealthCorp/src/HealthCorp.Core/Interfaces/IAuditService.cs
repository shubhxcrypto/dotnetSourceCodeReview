using HealthCorp.Core.Entities;
using System.Threading.Tasks;

namespace HealthCorp.Core.Interfaces;

public interface IAuditService
{
    Task LogAsync(string action, string username, string details);
    Task LogSensitiveAsync(string action, string username, object sensitiveData); // Vulnerable function
}
