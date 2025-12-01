using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using ShopApi.Models;
using ShopApi.Models.Enums;

namespace ShopApi.Security.Licensing
{
	public class LicenseManager : ILicenseManager
	{
		public TokenDbContext TokenDbContext { get; }
		public ShopDbContext ShopDbContext { get; }

		public LicenseManager(TokenDbContext tokenDbContext, ShopDbContext dbContext)
		{
			TokenDbContext = tokenDbContext;
			ShopDbContext = dbContext;
		}
		public async Task TryLogin(string userDbName, string IpAddres, ELoginType loginType, string ssaid = null)
		{
			var user = await ShopDbContext.Users.Where(u => u.Username == userDbName)
				.Include(u => u.RoleForUsers)
				.ThenInclude(ru => ru.UserRole)
				.FirstOrDefaultAsync();

			if (user.RoleForUsers.Any(s => s.UserRole.Code == "ADM")) return; //ignore licenses for admin roles.


			if (loginType != ELoginType.Mobile || loginType != ELoginType.Web) // License validation for PC/External system ends here
				return;

			var devicesLoggedIn = await GetLoggedInDevices(loginType, ssaid);

			if (devicesLoggedIn.Any(d => d.Username == userDbName)) //log out the same user on different device
			{
				var sameUserOnDiffDevice = devicesLoggedIn.FirstOrDefault(d => d.Username == userDbName);
				TokenDbContext.ShopApiTokens.Remove(sameUserOnDiffDevice);
				await TokenDbContext.SaveChangesAsync();

				devicesLoggedIn = await GetLoggedInDevices(loginType, ssaid); //refresh logged in devices
			}
		}

		private async ValueTask<List<ShopApiToken>> GetLoggedInDevices(ELoginType loginType, string ssaid) => await TokenDbContext.ShopApiTokens
				.Where(s => s.LoginType == loginType)
				.Where(s => s.ExpirationDate >= DateTime.Now)   //only valid tokens
				.Where(s => s.SSAID != ssaid)                   //only different devices than current
				.Where(s => !s.Roles.Contains("ADM", StringComparison.OrdinalIgnoreCase)) //ignore ADMIN 
				.ToListAsync();
	}
}
