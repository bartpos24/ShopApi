using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using ShopApi.Interfaces.Services;
using ShopApi.Models;
using ShopApi.Models.Database;
using ShopApi.Models.TransferObject;
using System.IdentityModel.Tokens.Jwt;

namespace ShopApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ShopController
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly UserManager<IdentityUser> userManager;
        private readonly IConfiguration config;
        private readonly IAuthService authService;
		public LoginController(SignInManager<IdentityUser> _signInManager, UserManager<IdentityUser> _userManager, IAuthService _authService, IConfiguration _config, ShopDbContext context, ILogger<LoginController> logger) : base(context, logger)
        {
            //signInManager = _signInManager;
            config = _config;
            //userManager = _userManager;
			authService = _authService;
		}
        [AllowAnonymous]
        [HttpPost]
		[Route("[action]")]
		public async Task<ActionResult<TokenResponse>> Login([FromBody] LoginModel loginModel)
        {
            if(!ModelState.IsValid)
			{
				var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
				return BadRequest($"Błędy walidacji: {errors}");
			}

			if(string.IsNullOrEmpty(loginModel.SSAID))
				return BadRequest("SSAID jest wymagane w procesie logowania");

			var user = await Context.Users
				.Include(u => u.RoleForUsers)
				.ThenInclude(ru => ru.UserRole)
				.FirstOrDefaultAsync(u => u.Username == loginModel.Username);

			if(user == null)
				return NotFound($"Użytkownik o nazwie {loginModel.Username} nie istnieje");
			if(!authService.VerifyPassword(user, loginModel.Passowrd))
				return Unauthorized("Nieprawidłowy login lub hasło");

			var roles = user.RoleForUsers
				.Select(ru => ru.UserRole.Code)
				.ToList();

			var tokenResponse = authService.GenerateToken(user, loginModel.SSAID, roles);
			return Ok(tokenResponse);
		}

		[AllowAnonymous]
		[HttpPost]
		[Route("[action]")]
		public async Task<IActionResult> Register([FromBody] RegisterModel userToRegister)
        {
            if(!ModelState.IsValid)
			{
                var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
				return BadRequest($"Błędy walidacji: {errors}");
			}
			if (await Context.Users.AnyAsync(u => u.Username == userToRegister.Username))
				return BadRequest($"Użytkownik o nazwie {userToRegister.Username} już istnieje");
            if(await Context.Users.AnyAsync(u => u.Email == userToRegister.Email))
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

			if (user.Id > 0)
			{
                
			}
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
        private bool AuthenticateUser(LoginModel loginModel)
        {
            var result = signInManager.PasswordSignInAsync(loginModel.Username, loginModel.Passowrd, true, lockoutOnFailure: false).Result;
            return result.Succeeded;
        }
    }
}
