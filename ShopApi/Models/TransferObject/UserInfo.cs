namespace ShopApi.Models.TransferObject
{
	public class UserInfo
	{
		public int Id { get; set; }
		public string Name { get; set; }
		public string Surname { get; set; }
		public string Username { get; set; }
		public string Email { get; set; }
		public List<string> Roles { get; set; } = new List<string>();
	}
}
