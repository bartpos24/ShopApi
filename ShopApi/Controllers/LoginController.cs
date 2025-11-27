using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using ShopApi.Interfaces.Services;
using ShopApi.Models;
using ShopApi.Models.Database;
using ShopApi.Models.Enums;
using ShopApi.Models.TransferObject;
using System.IdentityModel.Tokens.Jwt;

namespace ShopApi.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class LoginController : ShopController
	{
		private TokenDbContext TokenContext { get; }
		private readonly IConfiguration config;
		private readonly IAuthService authService;
		public LoginController(IAuthService _authService, IConfiguration _config, TokenDbContext tokenDbContext, ShopDbContext context, ILogger<LoginController> logger) : base(context, logger)
		{
			TokenContext = tokenDbContext;
			config = _config;
			authService = _authService;
		}
		[AllowAnonymous]
		[HttpPost]
		[Route("[action]")]
		public async Task<ActionResult<string>> Login([FromBody] LoginModel loginModel)
		{
			if (!ModelState.IsValid)
			{
				var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
				return BadRequest($"Błędy walidacji: {errors}");
			}

			if (loginModel.LoginType == ELoginType.Mobile && string.IsNullOrEmpty(loginModel.SSAID))
				return BadRequest("SSAID jest wymagane w procesie logowania");

			var user = await Context.Users
				.Include(u => u.RoleForUsers)
				.ThenInclude(ru => ru.UserRole)
				.FirstOrDefaultAsync(u => u.Username == loginModel.Username);

			if (user == null)
				return NotFound($"Użytkownik o nazwie {loginModel.Username} nie istnieje");
			if (!authService.VerifyPassword(user, loginModel.Password))
				return Unauthorized("Nieprawidłowy login lub hasło");

			var roles = user.RoleForUsers
				.Select(ru => ru.UserRole.Code)
				.ToList();

			var tokenResponse = authService.GenerateToken(user, loginModel.SSAID, roles);
			var exisitingToken = await TokenContext.ShopApiTokens
				.FirstOrDefaultAsync(shopApiToken => 
					shopApiToken.Username == loginModel.Username && 
					shopApiToken.LoginType == loginModel.LoginType && 
					shopApiToken.LastActivity.IpAddress == HttpContext.Connection.RemoteIpAddress.ToString() && 
					(shopApiToken.SSAID == loginModel.SSAID || loginModel.SSAID == null));
			if(exisitingToken == null)
			{
				await TokenContext.ShopApiTokens.AddAsync(new ShopApiToken
				{
					Guid = Guid.Parse(tokenResponse.Id),
					Username = loginModel.Username,
					LoginType = loginModel.LoginType,
					SSAID = loginModel.SSAID,
					ExpirationDate = authService.GetTokenExpiry(),
					Roles = string.Join(",", roles),
					LastActivity = new UserActivity
					{
						IpAddress = HttpContext.Connection.RemoteIpAddress.ToString(),
						LastActivity = DateTime.Now,
						UserAgent = Request.Headers["User-Agent"]
					}
				});
			} else
			{
				//exisitingToken.Guid = Guid.Parse(tokenResponse.AccessToken);
				exisitingToken.ExpirationDate = authService.GetTokenExpiry();
			}
			await TokenContext.SaveChangesAsync();
			var tokenString = new JwtSecurityTokenHandler().WriteToken(tokenResponse);
			return !string.IsNullOrEmpty(tokenString) ? Ok(tokenString) : NotFound("Wystąpił błąd podczas logowania użytkownika");

		}

		[AllowAnonymous]
		[HttpPost]
		[Route("[action]")]
		public async Task<ActionResult<string>> Refresh([FromBody] string accessToken, [FromQuery] string? SSAID = null)
		{
			if (!authService.ValidateAccessToken(accessToken))
				return BadRequest("Nieprawidłowy token dostępu");
			var token = new JwtSecurityToken(accessToken);
			if (!await TokenContext.ShopApiTokens.AnyAsync(validToken => validToken.Guid == Guid.Parse(token.Id)))
				return BadRequest("Nieprawidłowy token dostępu");

			var user = authService.GetUserFromToken(token);
			if (user == null)
				return NotFound();
			var roles = user.RoleForUsers
				.Select(ru => ru.UserRole.Code)
				.ToList();

			var newToken = authService.GenerateToken(user, SSAID, roles);

			var oldToken = await TokenContext.ShopApiTokens
				.FirstOrDefaultAsync(shopApiToken => shopApiToken.Guid == Guid.Parse(token.Id));
			TokenContext.ShopApiTokens.Remove(oldToken);
			await TokenContext.ShopApiTokens.AddAsync(new ShopApiToken
			{
				Guid = Guid.Parse(newToken.Id),
				Username = user.Username,
				LoginType = oldToken.LoginType,
				SSAID = SSAID ?? oldToken.SSAID,
				ExpirationDate = authService.GetTokenExpiry(),
				Roles = string.Join(",", roles),
				LastActivity = new UserActivity
				{
					IpAddress = HttpContext.Connection.RemoteIpAddress.ToString(),
					LastActivity = DateTime.Now,
					UserAgent = Request.Headers["User-Agent"]
				}
			});
			await TokenContext.SaveChangesAsync();
			var tokenString = new JwtSecurityTokenHandler().WriteToken(newToken);
			return Ok(tokenString);
		}

		[AllowAnonymous]
		[HttpPost]
		[Route("[action]")]
		public async Task<IActionResult> Register([FromBody] RegisterModel userToRegister)
		{
			if (!ModelState.IsValid)
			{
				var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
				return BadRequest($"Błędy walidacji: {errors}");
			}
			if (await Context.Users.AnyAsync(u => u.Username == userToRegister.Username))
				return BadRequest($"Użytkownik o nazwie {userToRegister.Username} już istnieje");
			if (await Context.Users.AnyAsync(u => u.Email == userToRegister.Email))
				return BadRequest($"Użytkownik o adresie email {userToRegister.Email} już istnieje");

			var defaultRole = await Context.UserRoles
					.FirstOrDefaultAsync(r => r.Code == "USR");

			var user = new User
			{
				Username = userToRegister.Username,
				Email = userToRegister.Email,
				Name = userToRegister.Name,
				Surname = userToRegister.Surname,
				CreatedAt = DateTime.Now
			};

			user.Passowrd = authService.HashPassword(user, userToRegister.Password);
			Context.Add(user);
			await Context.SaveChangesAsync();

			if (user.Id > 0 && defaultRole != null && defaultRole.Id > 0)
			{
				var roleForUser = new RoleForUser
				{
					UserId = user.Id,
					UserRoleId = defaultRole.Id,
				};
				Context.Add(roleForUser);
				await Context.SaveChangesAsync();
				return Ok("Pomyślnie zarejestrowano użytkownika");
			}

			return BadRequest("Wystąpił błąd podczas rejestracji użytkownika");


			//         var result = await Context.Users.AddAsync(user);
			//if (result)
			//             return Ok("Pomyślnie zarejestrowano użytkownika");
			//         return BadRequest(result);

			//var newUser = new IdentityUser { UserName = user.Username, Email = user.Email };
			//         var result = await userManager.CreateAsync(newUser, user.Passowrd);
			//if (result.Succeeded)
			//    return Ok($"Pomyślnie dodano użytkownika {user.UserName}");
			//else
			//    return NotFound($"Wystąpił błąd dodawania użytkownika. {result.Errors.FirstOrDefault()}");
		}

		[AllowAnonymous]
		[HttpPost]
		[Route("[action]")]
		public async Task<IActionResult> Logout()
		{
			//var loginType = HttpContext.User.Claims
			var token = await TokenContext.ShopApiTokens.FirstOrDefaultAsync(w => w.Username == HttpContext.User.Identity.Name);
			if (token == null)
			{
				return NotFound();
			}

			var user = await Context.Users.FirstOrDefaultAsync(u => u.Username == token.Username);

			//var loginLog = await Context.Sa
			TokenContext.ShopApiTokens.Remove(token);
			await TokenContext.SaveChangesAsync();
			return Ok("Pomyślnie wylogowano użytkownika");
		}

		private string GenerateJsonWebToken(LoginModel loginModel)
		{
			var securityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(config["Jwt:JWTAccessSecretKey"]));
			var creadentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
			var token = new JwtSecurityToken(config["Jwt:Issuer"], config["Jwt:Audience"], null,
					expires: DateTime.Now.AddMinutes(120),
					signingCredentials: creadentials
			);
			return new JwtSecurityTokenHandler().WriteToken(token);
		}
	}
}
