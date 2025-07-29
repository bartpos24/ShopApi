using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using ShopApi.Interfaces.Services;
using ShopApi.Models;
using ShopApi.Models.Database;
using ShopApi.Models.TransferObject;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static Dapper.SqlMapper;
//using YourApp.Models;

namespace ShopApi.Services
{
	public class AuthService : IAuthService
	{
		private readonly ShopDbContext context;
		//private readonly IJwtService jwtService;
		private readonly ILogger<AuthService> logger;
		private readonly IPasswordHasher<User> passwordHasher;
		private readonly IConfiguration configuration;
		public AuthService(ShopDbContext _context, ILogger<AuthService> _logger, IPasswordHasher<User> _passwordHasher, IConfiguration _configuration)
		{
			context = _context;
			//jwtService = _jwtService;
			logger = _logger;
			passwordHasher = _passwordHasher;
			configuration = _configuration;
		}
		public string HashPassword(User user, string password)
		{
			var hashedPassword = passwordHasher.HashPassword(user, password);

			return hashedPassword;
		}
		public bool VerifyPassword(User user, string password)
		{
			var verificationResult = passwordHasher.VerifyHashedPassword(user, user.Passowrd, password);
			return verificationResult == PasswordVerificationResult.Success;
		}
		public TokenResponse GenerateToken(User user, string SSAID, List<string> roles)
		{
			return new TokenResponse
			{
				AccessToken = GenerateAccessToken(user, SSAID, roles),
				RefreshToken = GenerateRefreshToken(user, SSAID, roles),
				AccessTokenExpiry = DateTime.UtcNow.AddMinutes(int.Parse(configuration["Jwt:AccessTokenExpiryMinutes"])),
				RefreshTokenExpiry = DateTime.UtcNow.AddMinutes(int.Parse(configuration["Jwt:RefreshTokenExpiryMinutes"])),
				User = new UserInfo
				{
					Id = user.Id,
					Name = user.Name,
					Surname = user.Surname,
					Username = user.Username,
					Email = user.Email,
					Roles = roles
				}
			};
		}
		private string GenerateRefreshToken(User user, string SSAID, List<string> roles)
		{
			var claims = new List<Claim>
			{
				new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
				new Claim(ClaimTypes.Name, user.Username),
				new Claim(ClaimTypes.Email, user.Email),
				new Claim("name", user.Name),
				new Claim("surname", user.Surname),
				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unikalny identyfikator tokenu
                new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
			};

			// Dodanie ról jako osobnych claimów
			foreach (var role in roles)
			{
				claims.Add(new Claim(ClaimTypes.Role, role));
			}

			// Dodanie SSAID jeśli jest podane
			if (!string.IsNullOrEmpty(SSAID))
			{
				claims.Add(new Claim("ssaid", SSAID));
			}

			// Klucz symetryczny do podpisania tokenu
			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:JWTRefreshSecretKey"]));
			var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

			// Utworzenie tokenu
			var token = new JwtSecurityToken(
				issuer: configuration["Jwt:Issuer"],
				audience: configuration["Jwt:Audience"],
				claims: claims,
				expires: DateTime.UtcNow.AddMinutes(int.Parse(configuration["Jwt:RefreshTokenExpiryMinutes"])),
				signingCredentials: credentials
			);
			return new JwtSecurityTokenHandler().WriteToken(token);
		}
		private string GenerateAccessToken(User user, string SSAID, List<string> roles)
		{
			var claims = new List<Claim>
			{
				new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
				new Claim(ClaimTypes.Name, user.Username),
				new Claim(ClaimTypes.Email, user.Email),
				new Claim("name", user.Name),
				new Claim("surname", user.Surname),
				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unikalny identyfikator tokenu
                new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
			};

			// Dodanie ról jako osobnych claimów
			foreach (var role in roles)
			{
				claims.Add(new Claim(ClaimTypes.Role, role));
			}

			// Dodanie SSAID jeśli jest podane
			if (!string.IsNullOrEmpty(SSAID))
			{
				claims.Add(new Claim("ssaid", SSAID));
			}

			// Klucz symetryczny do podpisania tokenu
			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:JWTAccessSecretKey"]));
			var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

			// Utworzenie tokenu
			var token = new JwtSecurityToken(
				issuer: configuration["Jwt:Issuer"],
				audience: configuration["Jwt:Audience"],
				claims: claims,
				expires: DateTime.UtcNow.AddMinutes(int.Parse(configuration["Jwt:AccessTokenExpiryMinutes"])),
				signingCredentials: credentials
			);
			return new JwtSecurityTokenHandler().WriteToken(token);
		}
		//public async Task<IActionResult> RegisterUser(RegisterModel userToRegister)
		//{
		//	try
		//	{
		//		if(await context.Users.AnyAsync(u => u.Username == userToRegister.Username))
		//			return BadRequest($"Użytkownik o nazwie {userToRegister.Username} już istnieje");
		//	} catch(Exception ex)
		//	{
		//		logger.LogError(ex, "Błąd podczas rejestracji użytkownika");
		//		return Task.FromResult<IActionResult>(new BadRequestObjectResult("Wystąpił błąd podczas rejestracji użytkownika"));
		//	}
		//}
	}
}
