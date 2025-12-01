using System.IdentityModel.Tokens.Jwt;
using DotnetJwtAuthTemplate.DTOs;
using DotnetJwtAuthTemplate.Models;
using DotnetJwtAuthTemplate.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace DotnetJwtAuthTemplate.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ITokenService _tokenService;

    public AuthController(UserManager<ApplicationUser> userManager, ITokenService tokenService)
    {
        _userManager = userManager;
        _tokenService = tokenService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] AuthDtos.RegisterRequest request)
    {
        var user = new ApplicationUser { UserName = request.UserName ?? request.Email, Email = request.Email };
        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        return Ok();
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] AuthDtos.LoginRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null) return Unauthorized();
        if (!await _userManager.CheckPasswordAsync(user, request.Password)) return Unauthorized();
        var accessToken = _tokenService.CreateAccessToken(user);
        var refreshToken = await _tokenService.CreateRefreshTokenAsync(user.Id,
            HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");
        //ser http only cookie for refresh token
        Response.Cookies.Append("refreshToken", refreshToken.Token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = refreshToken.Expires
        });
        return Ok(new AuthDtos.AuthResponse(accessToken));
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh()
    {
        if (!Request.Cookies.TryGetValue("refreshToken", out var token)) return Unauthorized();
        var rt = await _tokenService.GetRefreshTokenAsync(token);
        if (rt == null || !rt.IsActive) return Unauthorized();
        //rotate token
        var newRt = await _tokenService.RotateRefreshTokenAsync(rt,
            HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown");

        var user = await _userManager.FindByIdAsync(newRt.UserId);
        if (user == null) return Unauthorized();

        var newAccessToken = _tokenService.CreateAccessToken(user);
        //set new refresh token in http only cookie
        Response.Cookies.Append("refreshToken", newRt.Token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = newRt.Expires
        });

        return Ok(new AuthDtos.AuthResponse(newAccessToken));
    }
    [Authorize]
    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;        if(userId == null) return Unauthorized();
        var user = await _userManager.FindByIdAsync(userId);
        if(user == null) return Unauthorized();
        return Ok(new { user.Id, user.UserName, user.Email });
    }
}