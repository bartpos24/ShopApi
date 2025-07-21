using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using ShopApi.Models;
using ShopApi.Models.TransferObject;
using System.IdentityModel.Tokens.Jwt;

namespace ShopApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ShopController
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly IConfiguration config;
        public LoginController(SignInManager<IdentityUser> _signInManager, IConfiguration _config, ShopDbContext context, ILogger logger) : base(context, logger)
        {
            signInManager = _signInManager;
            config = _config;
        }
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            IActionResult response = Unauthorized();
            var success = AuthenticateUser(loginModel);
            if (success)
            {
                var tokenString = GenerateJsonWebToken(loginModel);
                response = Ok(new { token = tokenString });
            }
            return response;
        }

        public string GenerateJsonWebToken(LoginModel loginModel)
        {
            var securityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(config["Jwt:JWTAccessSecretKey"]));
            var creadentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(config["Jwt:Issuer"], config["Jwt:Audience"], null,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: creadentials
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        public bool AuthenticateUser(LoginModel loginModel)
        {
            var result = signInManager.PasswordSignInAsync(loginModel.Username, loginModel.Passowrd, true, lockoutOnFailure: false).Result;
            return result.Succeeded;
        }
    }
}
