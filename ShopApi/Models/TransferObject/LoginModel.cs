using ShopApi.Models.Enums;
using System.ComponentModel.DataAnnotations;

namespace ShopApi.Models.TransferObject
{
    public class LoginModel
    {
		[Required(ErrorMessage = "Login jest wymagany")]
		public string Username { get; set; }
		[Required(ErrorMessage = "Hasło jest wymagane")]
		public string Passowrd { get; set; }
        public string? SSAID { get; set; }
        public ELoginType LoginType { get; set; }
    }
}
