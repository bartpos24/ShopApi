using Microsoft.AspNetCore.Mvc;
using ShopApi.Models.Database;
using ShopApi.Models.Enums;
using ShopApi.Models.TransferObject;
using System.IdentityModel.Tokens.Jwt;

namespace ShopApi.Interfaces.Services
{
	public interface IAuthService
	{
		string HashPassword(User user, string password);
		bool VerifyPassword(User user, string password);
		JwtSecurityToken GenerateToken(User user, string SSAID, List<string> roles, ELoginType loginType);
		DateTime GetTokenExpiry();
		bool ValidateAccessToken(string token);
		User? GetUserFromToken(JwtSecurityToken token);
		ELoginType GetLoginTypeFromToken(JwtSecurityToken token);
	}
}
