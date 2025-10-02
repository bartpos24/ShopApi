using ShopApi.Models.Enums;

namespace ShopApi.Models
{
	public class ShopApiToken
	{
		public int Id { get; set; }
		public Guid Guid { get; set; }
		public string Username { get; set; } = default!;
		public string SSAID { get; set; } = default!;
		public string Roles { get; set; } = default!;
		public DateTime ExpirationDate { get; set; }
		public ELoginType LoginType { get; set; }
		public UserActivity LastActivity { get; set; } = default!;

	}
}
