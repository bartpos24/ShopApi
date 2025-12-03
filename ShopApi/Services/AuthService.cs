using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using ShopApi.Interfaces.Services;
using ShopApi.Models;
using ShopApi.Models.Database;
using ShopApi.Models.Enums;
using ShopApi.Models.TransferObject;
using ShopApi.Utilities;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using static Dapper.SqlMapper;
using static ShopApi.Extensions.ClaimsPrincipalExtensions;

namespace ShopApi.Services
{
	public class AuthService : IAuthService
	{
		private readonly ShopDbContext context;
		private IServiceProvider ServiceProvider { get; }
		private TokenSettings Settings => ServiceProvider.GetSettings<TokenSettings>();
		private readonly ILogger<AuthService> logger;
		private readonly IPasswordHasher<User> passwordHasher;
		public AuthService(ShopDbContext _context, ILogger<AuthService> _logger, IPasswordHasher<User> _passwordHasher, IConfiguration _configuration, IServiceProvider serviceProvider)
		{
			context = _context;
			logger = _logger;
			passwordHasher = _passwordHasher;
			ServiceProvider = serviceProvider;
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
		public JwtSecurityToken GenerateToken(User user, string SSAID, List<string> roles, ELoginType loginType)
		{
			return GenerateAccessToken(user, SSAID, roles, loginType);
		}

		public DateTime GetTokenExpiry()
		{
			return DateTime.UtcNow.AddMinutes(Settings.AccessTokenExpiryMinutes);
		}
		private string GenerateRefreshToken(User user, string SSAID, List<string> roles, ELoginType loginType)
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
			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Settings.JWTAccessSecretKey));
			var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

			// Utworzenie tokenu
			var token = new JwtSecurityToken(
				issuer: Settings.Issuer,
				audience: Settings.Audience,
				claims: claims,
				expires: DateTime.UtcNow.AddMinutes(Settings.RefreshTokenExpiryMinutes),
				signingCredentials: credentials
			);
			return new JwtSecurityTokenHandler().WriteToken(token);
		}
		private JwtSecurityToken GenerateAccessToken(User user, string SSAID, List<string> roles, ELoginType loginType)
		{
			var claims = new List<Claim>
			{
				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unikalny identyfikator tokenu
				new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
				new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
				new Claim(ClaimTypes.Name, user.Name),
				new Claim(ClaimTypes.Surname, user.Surname),
				new Claim(ClaimTypes.Email, user.Email),
				new Claim(ShopLoginClaimsKey, loginType.ToString()),
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
			var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Settings.JWTAccessSecretKey));
			var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

			// Utworzenie tokenu
			var token = new JwtSecurityToken(
				issuer: Settings.Issuer,
				audience: Settings.Audience,
				claims: claims,
				expires: DateTime.UtcNow.AddMinutes(Settings.AccessTokenExpiryMinutes),
				signingCredentials: credentials
			);
			//return new JwtSecurityTokenHandler().WriteToken(token);
			return token;
		}

		public bool ValidateAccessToken(string token)
		{
			var tokenHandler = new JwtSecurityTokenHandler();
			var key = Encoding.UTF8.GetBytes(Settings.JWTAccessSecretKey);
			try
			{
				tokenHandler.ValidateToken(token, new TokenValidationParameters
				{
					ValidateIssuerSigningKey = true,
					IssuerSigningKey = new SymmetricSecurityKey(key),
					ValidateIssuer = true,
					ValidIssuer = Settings.Issuer,
					ValidateAudience = true,
					ValidAudience = Settings.Audience,
					//ClockSkew = TimeSpan.Zero // Eliminuje domyślny czas tolerancji 5 minut
				}, out SecurityToken validatedToken);
				return true; // Token jest ważny
			}
			catch (SecurityTokenValidationException validationException)
			{
				logger.LogInformation($"Token is not Valid: {validationException.Message}");
				return false;
			}
			catch (ArgumentException argException)
			{
				logger.LogInformation($"Wrong format: {argException.Message}");
				return false;
			}
			catch
			{
				return false; // Token jest nieważny
			}
		}
		public User? GetUserFromToken(JwtSecurityToken token)
		{
			int.TryParse(token.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value, out var userId);
			var username = token.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.UniqueName)?.Value;
			var email = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
			var name = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
			var surname = token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Surname)?.Value;

			return context.Users
				.Include(u => u.RoleForUsers)
				.ThenInclude(ru => ru.UserRole)
				.FirstOrDefault(u => u.Id == userId && u.Username == username && u.Email == email && u.Name == name && u.Surname == surname);
		}

		public ELoginType GetLoginTypeFromToken(JwtSecurityToken token)
		{
			Enum.TryParse(token.Claims.FirstOrDefault(c => c.Type == ShopLoginClaimsKey)?.Value, out ELoginType loginType);
			return loginType;
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
