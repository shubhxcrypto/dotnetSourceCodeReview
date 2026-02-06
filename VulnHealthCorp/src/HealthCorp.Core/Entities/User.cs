namespace HealthCorp.Core.Entities;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty; // Intentionally weak hashing later
    public string FullName { get; set; } = string.Empty;
    public string Role { get; set; } = "User"; // specific check for Admin/Manager
    public string? Email { get; set; }
    public bool IsActive { get; set; } = true;
}
