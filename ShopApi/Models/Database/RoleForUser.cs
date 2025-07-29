namespace ShopApi.Models.Database
{
	public class RoleForUser
	{
		public int UserId { get; set; }
		public int UserRoleId { get; set; }
		public virtual User User { get; set; }
		public virtual UserRole UserRole { get; set; }
	}
}
