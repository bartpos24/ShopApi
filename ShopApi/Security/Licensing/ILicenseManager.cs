using ShopApi.Models.Database;
using ShopApi.Models.Enums;

namespace ShopApi.Security.Licensing
{
	public interface ILicenseManager
	{
		Task TryLogin(User user, string IpAddres, ELoginType loginType, string? ssaid = null);
	}
}
