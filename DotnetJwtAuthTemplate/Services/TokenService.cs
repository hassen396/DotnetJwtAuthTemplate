using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using DotnetJwtAuthTemplate.Data;
using DotnetJwtAuthTemplate.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;


namespace DotnetJwtAuthTemplate.Services;

public class TokenService: ITokenService
{
    private readonly IConfiguration _config;
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _users;
    public TokenService(IConfiguration config, ApplicationDbContext context, UserManager<ApplicationUser> users)
    {
        _config = config;
        _context = context;
        _users = users;
    }
    public string CreateAccessToken(ApplicationUser user)
    {
       var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
       var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

       var claims = new List<Claim>
       {
           new Claim(JwtRegisteredClaimNames.Sub, user.Id),
           new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName ?? string.Empty),
           new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty)
       };
       var token = new JwtSecurityToken(
           issuer: _config["Jwt:Issuer"],
           audience: _config["Jwt:Audience"],
           claims: claims,
           expires: DateTime.UtcNow.AddMinutes(double.Parse(_config["Jwt:AccessTokenExpirationMinutes"]!)),
           signingCredentials: creds
       );
       return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public async Task<RefreshToken> CreateRefreshTokenAsync(string userId, string createdByIp)
    {
        var rt = new RefreshToken
        {
            Token = RandomTokenString(),
            Expires = DateTime.UtcNow.AddDays(double.Parse(_config["Jwt:RefreshTokenExpirationDays"]!)),
            Created = DateTime.UtcNow,
            CreatedByIp = createdByIp,
            UserId = userId
        };
        _context.RefreshTokens.Add(rt);
        await  _context.SaveChangesAsync();
        return rt;
    }
    

    public async Task<RefreshToken> RotateRefreshTokenAsync(RefreshToken currentToken, string createdByIp)
    {
        // Revoke current token and create a new one
        var newToken = new RefreshToken
        {
            Token = RandomTokenString(),
            Expires = DateTime.UtcNow.AddDays(double.Parse(_config["Jwt:RefreshTokenExpirationDays"]!)),
            Created = DateTime.UtcNow,
            CreatedByIp = createdByIp,
            UserId = currentToken.UserId
        };
        currentToken.Revoked = DateTime.UtcNow;
        currentToken.RevokedByIp = createdByIp;
        currentToken.ReplacedByToken = newToken.Token;
        
        _context.RefreshTokens.Update(currentToken);
        _context.RefreshTokens.Add(newToken);
        await _context.SaveChangesAsync();
        return newToken;
    }

    public async Task<RefreshToken> GetRefreshTokenAsync(string token)
    {
        return await _context.RefreshTokens.FirstOrDefaultAsync(t => t.Token == token);
    }

    public Task RevokeRefreshTokenAsync(RefreshToken token, string revokedByIp, string? revokedBy = null)
    {
        token.Revoked = DateTime.UtcNow;
        token.RevokedByIp = revokedByIp;
        //TODO: add replaced by token logic
        // token.ReplacedByToken = replacedBy;
        _context.RefreshTokens.Update(token);
        return _context.SaveChangesAsync();
    }

    private static string RandomTokenString()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
}