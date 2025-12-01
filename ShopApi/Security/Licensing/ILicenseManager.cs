using ShopApi.Models.Enums;

namespace ShopApi.Security.Licensing
{
	public interface ILicenseManager
	{
		Task TryLogin(string userDbName, string IpAddres, ELoginType loginType, string? ssaid = null);
	}
}
