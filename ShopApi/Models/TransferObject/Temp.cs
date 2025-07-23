//Przedstawię pełną implementację systemu autoryzacji i autentykacji JWT w .NET 8. Omówię każdy element szczegółowo.

//1. Modele danych
//Klasa User
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using ShopApi.Migrations;
using ShopApi.Models.Database;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using YourApp.Data;
using YourApp.DTOs;
using YourApp.Enums;
using YourApp.Services;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace YourApp.Models
{
    public class User
    {
        [Key] // Oznacza klucz główny tabeli
        public int Id { get; set; }

        [Required] // Pole wymagane w bazie danych
        [MaxLength(50)] // Maksymalna długość 50 znaków
        public string Name { get; set; }

        [Required]
        [MaxLength(50)]
        public string Surname { get; set; }

        [Required]
        [MaxLength(50)]
        [Column(TypeName = "varchar(50)")] // Określa typ kolumny w SQL
        public string Username { get; set; }

        [Required]
        [EmailAddress] // Walidacja formatu email
        [MaxLength(100)]
        public string Email { get; set; }

        [Required]
        [MaxLength(255)] // Hasło będzie zahashowane, więc potrzebujemy więcej miejsca
        public string Password { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }

        // Właściwość nawigacyjna dla relacji wiele do wielu
        public virtual ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    }
}


//Klasa UserRole

using System.ComponentModel.DataAnnotations;

namespace YourApp.Models
{
    public class UserRole
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(20)]
        public string Code { get; set; } // np. "ADMIN", "USER", "MODERATOR"

        [Required]
        [MaxLength(50)]
        public string Name { get; set; } // np. "Administrator", "Użytkownik", "Moderator"

        public string? Description { get; set; }

        // Właściwość nawigacyjna dla relacji wiele do wielu
        public virtual ICollection<User> Users { get; set; } = new List<User>();
    }
}

//2. Enum dla miejsca logowania

namespace YourApp.Enums
{
    public enum LoginSource
    {
        Mobile = 1,
        Web = 2,
        External = 3,
        SSAID = 4
    }
}

//3.DTOs(Data Transfer Objects)
//DTO dla rejestracji


using System.ComponentModel.DataAnnotations;

namespace YourApp.DTOs
{
    public class RegisterDto
    {
        [Required(ErrorMessage = "Imię jest wymagane")]
        [StringLength(50, ErrorMessage = "Imię nie może być dłuższe niż 50 znaków")]
        public string Name { get; set; }

        [Required(ErrorMessage = "Nazwisko jest wymagane")]
        [StringLength(50, ErrorMessage = "Nazwisko nie może być dłuższe niż 50 znaków")]
        public string Surname { get; set; }

        [Required(ErrorMessage = "Login jest wymagany")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Login musi mieć od 3 do 50 znaków")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Email jest wymagany")]
        [EmailAddress(ErrorMessage = "Nieprawidłowy format email")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Hasło jest wymagane")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Hasło musi mieć od 6 do 100 znaków")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]",
            ErrorMessage = "Hasło musi zawierać małą literę, wielką literę, cyfrę i znak specjalny")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Potwierdzenie hasła jest wymagane")]
        [Compare("Password", ErrorMessage = "Hasła nie są identyczne")]
        public string ConfirmPassword { get; set; }
    }
}



//DTO dla logowania

using System.ComponentModel.DataAnnotations;
using YourApp.Enums;

namespace YourApp.DTOs
{
    public class LoginDto
    {
        [Required(ErrorMessage = "Login jest wymagany")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Hasło jest wymagane")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Źródło logowania jest wymagane")]
        public LoginSource LoginSource { get; set; }

        public string? SSAID { get; set; } // Opcjonalne, wymagane tylko dla LoginSource.SSAID
    }
}

//DTO dla odpowiedzi tokenu

namespace YourApp.DTOs
{
    public class TokenResponseDto
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTime AccessTokenExpiry { get; set; }
        public DateTime RefreshTokenExpiry { get; set; }
        public string TokenType { get; set; } = "Bearer";
        public UserInfoDto User { get; set; }
    }

    public class UserInfoDto
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Surname { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
    }
}



//4. DbContext

using Microsoft.EntityFrameworkCore;
using YourApp.Models;

namespace YourApp.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Konfiguracja relacji wiele do wielu między User i UserRole
            modelBuilder.Entity<User>()
                .HasMany(u => u.UserRoles)
                .WithMany(r => r.Users)
                .UsingEntity<Dictionary<string, object>>(
                    "UserUserRole", // Nazwa tabeli pośredniej
                    j => j.HasOne<UserRole>().WithMany().HasForeignKey("UserRoleId"),
                    j => j.HasOne<User>().WithMany().HasForeignKey("UserId"),
                    j =>
                    {
                        j.HasKey("UserId", "UserRoleId"); // Klucz złożony
                        j.ToTable("UserUserRoles"); // Nazwa tabeli w bazie
                    });

            // Indeksy dla wydajności
            modelBuilder.Entity<User>()
                .HasIndex(u => u.Username)
                .IsUnique(); // Unikatowy username

            modelBuilder.Entity<User>()
                .HasIndex(u => u.Email)
                .IsUnique(); // Unikatowy email

            modelBuilder.Entity<UserRole>()
                .HasIndex(r => r.Code)
                .IsUnique(); // Unikatowy kod roli

            // Seed data - początkowe role
            modelBuilder.Entity<UserRole>().HasData(
                new UserRole { Id = 1, Code = "ADMIN", Name = "Administrator", Description = "Pełny dostęp do systemu" },
                new UserRole { Id = 2, Code = "USER", Name = "Użytkownik", Description = "Podstawowy użytkownik systemu" },
                new UserRole { Id = 3, Code = "MODERATOR", Name = "Moderator", Description = "Moderator treści" }
            );
        }
    }
}


//5. Service JWT

using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using YourApp.Models;
using YourApp.Enums;

namespace YourApp.Services
{
    public interface IJwtService
    {
        string GenerateAccessToken(User user, IEnumerable<string> roles, LoginSource loginSource, string? ssaid = null);
        string GenerateRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
        bool ValidateToken(string token);
    }

    public class JwtService : IJwtService
    {
        private readonly IConfiguration _configuration;
        private readonly string _secretKey;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly int _accessTokenExpiryMinutes;
        private readonly int _refreshTokenExpiryDays;

        public JwtService(IConfiguration configuration)
        {
            _configuration = configuration;
            _secretKey = _configuration["Jwt:SecretKey"] ?? throw new ArgumentNullException("Jwt:SecretKey");
            _issuer = _configuration["Jwt:Issuer"] ?? throw new ArgumentNullException("Jwt:Issuer");
            _audience = _configuration["Jwt:Audience"] ?? throw new ArgumentNullException("Jwt:Audience");
            _accessTokenExpiryMinutes = int.Parse(_configuration["Jwt:AccessTokenExpiryMinutes"] ?? "15");
            _refreshTokenExpiryDays = int.Parse(_configuration["Jwt:RefreshTokenExpiryDays"] ?? "7");
        }

        public string GenerateAccessToken(User user, IEnumerable<string> roles, LoginSource loginSource, string? ssaid = null)
        {
            // Claims to informacje zawarte w tokenie
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim("name", user.Name),
                new Claim("surname", user.Surname),
                new Claim("loginSource", loginSource.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unikalny identyfikator tokenu
                new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            // Dodanie ról jako osobnych claimów
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            // Dodanie SSAID jeśli jest podane
            if (!string.IsNullOrEmpty(ssaid))
            {
                claims.Add(new Claim("ssaid", ssaid));
            }

            // Klucz symetryczny do podpisania tokenu
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Utworzenie tokenu
            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_accessTokenExpiryMinutes),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string GenerateRefreshToken()
        {
            // Refresh token to losowy ciąg bajtów zakodowany w Base64
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey)),
                ValidateLifetime = false, // Nie sprawdzamy czy token wygasł
                ValidIssuer = _issuer,
                ValidAudience = _audience,
                ClockSkew = TimeSpan.Zero
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }

        public bool ValidateToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(_secretKey);

                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = _issuer,
                    ValidAudience = _audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}



//6. Service autoryzacji


using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using YourApp.Data;
using YourApp.DTOs;
using YourApp.Models;
using YourApp.Enums;

namespace YourApp.Services
{
    public interface IAuthService
    {
        Task<ApiResponse<TokenResponseDto>> RegisterAsync(RegisterDto registerDto);
        Task<ApiResponse<TokenResponseDto>> LoginAsync(LoginDto loginDto);
        Task<ApiResponse<TokenResponseDto>> RefreshTokenAsync(string refreshToken);
        Task<ApiResponse<bool>> LogoutAsync(string refreshToken);
    }

    public class AuthService : IAuthService
    {
        private readonly ApplicationDbContext _context;
        private readonly IJwtService _jwtService;
        private readonly ILogger<AuthService> _logger;

        public AuthService(ApplicationDbContext context, IJwtService jwtService, ILogger<AuthService> logger)
        {
            _context = context;
            _jwtService = jwtService;
            _logger = logger;
        }

        public async Task<ApiResponse<TokenResponseDto>> RegisterAsync(RegisterDto registerDto)
        {
            try
            {
                // Sprawdzenie czy użytkownik już istnieje
                if (await _context.Users.AnyAsync(u => u.Username == registerDto.Username))
                {
                    return ApiResponse<TokenResponseDto>.Failure("Użytkownik o podanym loginie już istnieje");
                }

                if (await _context.Users.AnyAsync(u => u.Email == registerDto.Email))
                {
                    return ApiResponse<TokenResponseDto>.Failure("Użytkownik o podanym emailu już istnieje");
                }

                // Hashowanie hasła
                var hashedPassword = HashPassword(registerDto.Password);

                // Utworzenie nowego użytkownika
                var user = new User
                {
                    Name = registerDto.Name,
                    Surname = registerDto.Surname,
                    Username = registerDto.Username,
                    Email = registerDto.Email,
                    Password = hashedPassword,
                    CreatedAt = DateTime.UtcNow
                };

                // Dodanie domyślnej roli USER
                var userRole = await _context.UserRoles.FirstOrDefaultAsync(r => r.Code == "USER");
                if (userRole != null)
                {
                    user.UserRoles.Add(userRole);
                }

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                // Generowanie tokenów
                var roles = user.UserRoles.Select(r => r.Code).ToList();
                var accessToken = _jwtService.GenerateAccessToken(user, roles, LoginSource.Web);
                var refreshToken = _jwtService.GenerateRefreshToken();

                // Zapisanie refresh tokenu w bazie (opcjonalne)
                // Tutaj można dodać tabelę RefreshTokens

                var tokenResponse = new TokenResponseDto
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    AccessTokenExpiry = DateTime.UtcNow.AddMinutes(15),
                    RefreshTokenExpiry = DateTime.UtcNow.AddDays(7),
                    User = new UserInfoDto
                    {
                        Id = user.Id,
                        Name = user.Name,
                        Surname = user.Surname,
                        Username = user.Username,
                        Email = user.Email,
                        Roles = roles
                    }
                };

                _logger.LogInformation("Użytkownik {Username} został zarejestrowany", user.Username);
                return ApiResponse<TokenResponseDto>.Success(tokenResponse, "Rejestracja zakończona sukcesem");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Błąd podczas rejestracji użytkownika {Username}", registerDto.Username);
                return ApiResponse<TokenResponseDto>.Failure("Wystąpił błąd podczas rejestracji");
            }
        }

        public async Task<ApiResponse<TokenResponseDto>> LoginAsync(LoginDto loginDto)
        {
            try
            {
                // Walidacja SSAID dla LoginSource.SSAID
                if (loginDto.LoginSource == LoginSource.SSAID && string.IsNullOrEmpty(loginDto.SSAID))
                {
                    return ApiResponse<TokenResponseDto>.Failure("SSAID jest wymagane dla tego typu logowania");
                }

                // Pobranie użytkownika z rolami
                var user = await _context.Users
                    .Include(u => u.UserRoles)
                    .FirstOrDefaultAsync(u => u.Username == loginDto.Username);

                if (user == null)
                {
                    _logger.LogWarning("Nieudana próba logowania - użytkownik {Username} nie istnieje", loginDto.Username);
                    return ApiResponse<TokenResponseDto>.Failure("Nieprawidłowe dane logowania");
                }

                // Weryfikacja hasła
                if (!VerifyPassword(loginDto.Password, user.Password))
                {
                    _logger.LogWarning("Nieudana próba logowania - nieprawidłowe hasło dla użytkownika {Username}", loginDto.Username);
                    return ApiResponse<TokenResponseDto>.Failure("Nieprawidłowe dane logowania");
                }

                // Generowanie tokenów
                var roles = user.UserRoles.Select(r => r.Code).ToList();
                var accessToken = _jwtService.GenerateAccessToken(user, roles, loginDto.LoginSource, loginDto.SSAID);
                var refreshToken = _jwtService.GenerateRefreshToken();

                // Aktualizacja czasu ostatniego logowania
                user.UpdatedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                var tokenResponse = new TokenResponseDto
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    AccessTokenExpiry = DateTime.UtcNow.AddMinutes(15),
                    RefreshTokenExpiry = DateTime.UtcNow.AddDays(7),
                    User = new UserInfoDto
                    {
                        Id = user.Id,
                        Name = user.Name,
                        Surname = user.Surname,
                        Username = user.Username,
                        Email = user.Email,
                        Roles = roles
                    }
                };

                _logger.LogInformation("Użytkownik {Username} zalogował się z {LoginSource}", user.Username, loginDto.LoginSource);
                return ApiResponse<TokenResponseDto>.Success(tokenResponse, "Logowanie zakończone sukcesem");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Błąd podczas logowania użytkownika {Username}", loginDto.Username);
                return ApiResponse<TokenResponseDto>.Failure("Wystąpił błąd podczas logowania");
            }
        }

        public async Task<ApiResponse<TokenResponseDto>> RefreshTokenAsync(string refreshToken)
        {
            // Implementacja odświeżania tokenu
            // Tutaj powinna być logika sprawdzania refresh tokenu w bazie danych
            throw new NotImplementedException("Refresh token functionality requires additional implementation");
        }

        public async Task<ApiResponse<bool>> LogoutAsync(string refreshToken)
        {
            // Implementacja wylogowania
            // Tutaj powinna być logika usuwania refresh tokenu z bazy danych
            throw new NotImplementedException("Logout functionality requires additional implementation");
        }

        // Hashowanie hasła za pomocą BCrypt (zalecane)
        private string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, BCrypt.Net.BCrypt.GenerateSalt(12));
        }

        // Weryfikacja hasła
        private bool VerifyPassword(string password, string hashedPassword)
        {
            return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
        }
    }
}


//7. Klasa pomocnicza ApiResponse


namespace YourApp.DTOs
{
    public class ApiResponse<T>
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public T Data { get; set; }
        public List<string> Errors { get; set; } = new List<string>();

        public static ApiResponse<T> Success(T data, string message = "")
        {
            return new ApiResponse<T>
            {
                Success = true,
                Data = data,
                Message = message
            };
        }

        public static ApiResponse<T> Failure(string message, List<string> errors = null)
        {
            return new ApiResponse<T>
            {
                Success = false,
                Message = message,
                Errors = errors ?? new List<string>()
            };
        }
    }
}


//8. Controller


using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using YourApp.DTOs;
using YourApp.Services;

namespace YourApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// Rejestracja nowego użytkownika
        /// </summary>
        /// <param name="registerDto">Dane rejestracji</param>
        /// <returns>Token dostępu i refresh token</returns>
        [HttpPost("register")]
        [AllowAnonymous] // Pozwala na dostęp bez autoryzacji
        public async Task<ActionResult<ApiResponse<TokenResponseDto>>> Register([FromBody] RegisterDto registerDto)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
                return BadRequest(ApiResponse<TokenResponseDto>.Failure("Błędy walidacji", errors));
            }

            var result = await _authService.RegisterAsync(registerDto);

            if (result.Success)
            {
                return Ok(result);
            }

            return BadRequest(result);
        }

        /// <summary>
        /// Logowanie użytkownika
        /// </summary>
        /// <param name="loginDto">Dane logowania</param>
        /// <returns>Token dostępu i refresh token</returns>
        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<ActionResult<ApiResponse<TokenResponseDto>>> Login([FromBody] LoginDto loginDto)
        {
            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
                return BadRequest(ApiResponse<TokenResponseDto>.Failure("Błędy walidacji", errors));
            }

            var result = await _authService.LoginAsync(loginDto);

            if (result.Success)
            {
                return Ok(result);
            }

            return Unauthorized(result);
        }

        /// <summary>
        /// Odświeżenie tokenu dostępu
        /// </summary>
        /// <param name="refreshTokenDto">Refresh token</param>
        /// <returns>Nowy token dostępu</returns>
        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<ActionResult<ApiResponse<TokenResponseDto>>> RefreshToken([FromBody] RefreshTokenDto refreshTokenDto)
        {
            var result = await _authService.RefreshTokenAsync(refreshTokenDto.RefreshToken);

            if (result.Success)
            {
                return Ok(result);
            }

            return Unauthorized(result);
        }

        /// <summary>
        /// Wylogowanie użytkownika
        /// </summary>
        /// <returns>Potwierdzenie wylogowania</returns>
        [HttpPost("logout")]
        [Authorize] // Wymaga autoryzacji
        public async Task<ActionResult<ApiResponse<bool>>> Logout([FromBody] RefreshTokenDto refreshTokenDto)
        {
            var result = await _authService.LogoutAsync(refreshTokenDto.RefreshToken);

            if (result.Success)
            {
                return Ok(result);
            }

            return BadRequest(result);
        }

        /// <summary>
        /// Pobranie informacji o aktualnie zalogowanym użytkowniku
        /// </summary>
        /// <returns>Informacje o użytkowniku</returns>
        [HttpGet("me")]
        [Authorize]
        public ActionResult<ApiResponse<UserInfoDto>> GetCurrentUser()
        {
            var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var username = User.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value;
            var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
            var name = User.FindFirst("name")?.Value;
            var surname = User.FindFirst("surname")?.Value;
            var roles = User.FindAll(System.Security.Claims.ClaimTypes.Role).Select(c => c.Value).ToList();

            var userInfo = new UserInfoDto
            {
                Id = int.Parse(userId ?? "0"),
                Username = username,
                Email = email,
                Name = name,
                Surname = surname,
                Roles = roles
            };

            return Ok(ApiResponse<UserInfoDto>.Success(userInfo));
        }
    }

    public class RefreshTokenDto
    {
        public string RefreshToken { get; set; }
    }
}


//9. Konfiguracja w Program.cs

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using YourApp.Data;
using YourApp.Services;

var builder = WebApplication.CreateBuilder(args);

// Dodanie DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Dodanie serwisów
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IAuthService, AuthService>();

// Konfiguracja JWT Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"])),
        ClockSkew = TimeSpan.Zero // Brak tolerancji na różnice czasu
    };

    // Obsługa zdarzeń JWT
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            Console.WriteLine("Authentication failed: " + context.Exception.Message);
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            Console.WriteLine("Token validated successfully");
            return Task.CompletedTask;
        }
    };
});

// Dodanie autoryzacji
builder.Services.AddAuthorization(options =>
{
    // Definicja polityk autoryzacji
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("ADMIN"));
    options.AddPolicy("UserOrAdmin", policy => policy.RequireRole("USER", "ADMIN"));
    options.AddPolicy("ModeratorOrAdmin", policy => policy.RequireRole("MODERATOR", "ADMIN"));
});

builder.Services.AddControllers();

// Konfiguracja Swagger z obsługą JWT
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth API", Version = "v1" });

    // Dodanie definicji security dla JWT
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();

// Konfiguracja pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Kolejność middleware jest ważna!
app.UseAuthentication(); // Musi być przed UseAuthorization
app.UseAuthorization();

app.MapControllers();

app.Run();


//10. Konfiguracja appsettings.json

{
    "ConnectionStrings": {
        "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=YourAppDb;Trusted_Connection=true;MultipleActiveResultSets=true"
    },
  "Jwt": {
        "SecretKey": "YourSuperSecretKeyThatIsAtLeast32CharactersLong!",
    "Issuer": "YourApp",
    "Audience": "YourAppUsers",
    "AccessTokenExpiryMinutes": "15",
    "RefreshTokenExpiryDays": "7"
  },
  "Logging": {
        "LogLevel": {
            "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
        }
    },
  "AllowedHosts": "*"
}


//11. Migracje
//Po utworzeniu wszystkich klas, wykonaj następujące komendy w Package Manager Console:

# Dodanie migracji
Add - Migration InitialCreate

# Aktualizacja bazy danych
Update-Database


//12. Instalacja pakietów NuGet

    <PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer" Version="8.0.0" />
<PackageReference Include="Microsoft.EntityFrameworkCore.Tools" Version="8.0.0" />
<PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="8.0.0" />
<PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="7.0.3" />
<PackageReference Include="BCrypt.Net-Next" Version="4.0.3" />
<PackageReference Include="Swashbuckle.AspNetCore" Version="6.5.0" />



//Szczegółowe wyjaśnienie komponentów:
//Klasy modelu: User i UserRole z relacją wiele do wielu umożliwiają elastyczne zarządzanie rolami użytkowników.

//DTOs: Oddzielają model danych od API, zapewniając walidację i bezpieczeństwo.

//JWT Service: Generuje i waliduje tokeny, enkapsulując logikę JWT.

//Auth Service: Zawiera główną logikę autoryzacji, hashowanie haseł i zarządzanie użytkownikami.

//Controller: Udostępnia endpointy HTTP z odpowiednią autoryzacją.

//Konfiguracja: Program.cs konfiguruje wszystkie serwisy i middleware w odpowiedniej kolejności.

//System ten zapewnia bezpieczną autoryzację z wykorzystaniem standardów branżowych oraz możliwość łatwego rozszerzania o dodatkowe funkcjonalności.



