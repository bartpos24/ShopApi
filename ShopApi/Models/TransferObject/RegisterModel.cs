using Microsoft.AspNetCore.Identity;

namespace ShopApi.Models.TransferObject
{
	public class RegisterModel: IdentityUser
	{
		public string Username { get; set; }
		public string Email { get; set; }
		public string Password { get; set; }
		public string ConfirmPassword { get; set; }
		public string PIN { get; set; }
	}
}
