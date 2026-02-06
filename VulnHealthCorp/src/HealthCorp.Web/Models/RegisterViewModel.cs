using System.ComponentModel.DataAnnotations;

namespace HealthCorp.Web.Models;

public class RegisterViewModel
{
    [Required]
    public string Username { get; set; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [Required]
    [Compare("Password")]
    public string ConfirmPassword { get; set; } = string.Empty;

    [Required]
    public string FullName { get; set; } = string.Empty;
    
    [EmailAddress]
    public string? Email { get; set; }
}
