using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace DotnetJwtAuthTemplate.Models;

public class ApplicationUser : IdentityUser
{
    [MaxLength(255)]
    public string? FirstName { get; set; } = null!;
    
    [MaxLength(255)]
    public string? LastName { get; set; } = null!;
}