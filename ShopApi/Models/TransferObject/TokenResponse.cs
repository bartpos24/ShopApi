namespace ShopApi.Models.TransferObject
{
	public class TokenResponse
	{
		public string AccessToken { get; set; }
		public string RefreshToken { get; set; }
		public DateTime AccessTokenExpiry { get; set; }
		public DateTime RefreshTokenExpiry { get; set; }
		public string TokenType { get; set; } = "Bearer";
		public UserInfo User { get; set; }
	}
}
