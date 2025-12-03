namespace ShopApi.Utilities
{
	public class TokenSettings
	{
		public string Audience { get; set; }
		public string Issuer { get; set; }
		public string JWTAccessSecretKey { get; set; }
		public string JWTRefreshSecretKey { get; set; }
		public int AccessTokenExpiryMinutes { get; set; }
		public int RefreshTokenExpiryMinutes { get; set; }
		public DateTimeOffset TokenExpiryHourUtc { get; set; }
		public double ClockSkewSeconds { get; set; }
	}
}
