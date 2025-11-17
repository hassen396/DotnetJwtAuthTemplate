using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace DotnetJwtAuthTemplate.Models
{
    public class RefreshToken
    {
        [Key]
        public Guid Id { get; set; }

        [Required] public string Token { get; set; } = null!;
        
        public DateTime Expires { get; set; }
        public DateTime Created { get; set; }
        public string? CreatedByIp { get; set; }
        
        public DateTime? Revoked { get; set; }
        public string? RevokedByIp { get; set; }
        public string? ReplacedByToken { get; set; }
        
        [Required]
        public string UserId { get; set; } = null!;

        [NotMapped]
        public bool IsExpired => DateTime.UtcNow >= Expires;
        
        [NotMapped]
        public bool IsActive => Revoked == null && !IsExpired;
    }
}