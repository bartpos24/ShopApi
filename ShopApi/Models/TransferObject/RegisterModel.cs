using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace ShopApi.Models.TransferObject
{
	public class RegisterModel
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
		//[RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]",
		//	ErrorMessage = "Hasło musi zawierać małą literę, wielką literę, cyfrę i znak specjalny")]
		public string Password { get; set; }

		[Required(ErrorMessage = "Potwierdzenie hasła jest wymagane")]
		[Compare("Password", ErrorMessage = "Hasła nie są identyczne")]
		public string ConfirmPassword { get; set; }
	}
}
