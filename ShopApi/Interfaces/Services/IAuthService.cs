using Microsoft.AspNetCore.Mvc;
using ShopApi.Models.Database;
using ShopApi.Models.TransferObject;

namespace ShopApi.Interfaces.Services
{
	public interface IAuthService
	{
		string HashPassword(User user, string password);
		bool VerifyPassword(User user, string password);
		TokenResponse GenerateToken(User user, string SSAID, List<string> roles);
		//Task<IActionResult> RegisterUser(RegisterModel userToRegister);
	}
}
