namespace ShopApi.Models
{
	public class UserActivity
	{
		public string IpAddress { get; set; } = default!;
		public DateTime LastActivity { get; set; }
		public string? UserAgent { get; set; }
	}
}
