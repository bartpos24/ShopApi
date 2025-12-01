using Microsoft.AspNetCore.Authentication.JwtBearer;
using ShopApi.Extensions;
using ShopApi.Models;
using ShopApi.Models.Enums;
using ShopApi.Services;
using System.Security.Claims;
using System.Threading.Channels;

namespace ShopApi.Security
{
	public class TokenEvents : JwtBearerEvents
	{
		private ILogger<TokenEvents> Logger { get; }
		private IAuditActivityChannel Channel { get; }
		public TokenEvents(ILogger<TokenEvents> logger, TokenDbContext tokenContext)
		{
			Logger = logger;
			base.OnTokenValidated = OnTokenValidated;
		}
		private new async Task OnTokenValidated(TokenValidatedContext context)
		{
			var (isNumber, id, uid) = context.Principal.ShopUserId();
			if (!isNumber)
			{
				Logger.LogCritical($"Can't parse {uid} as UserId");
				throw new ArgumentException($"Cannot parse {uid} as shop user id.");
			}
			context.HttpContext.SetShopUserId(id);

			if (context.Principal.Identity.Name == null)
			{
				Logger.LogCritical("Can't obtain name from the token");
				throw new ArgumentException("Can't obtain name from the token");
			}
			var loginType = context.Principal.ShopLoginType();

			if (loginType == null)
			{
				Logger.LogCritical("Can't obtain license type from the token");
				throw new ArgumentException("Can't obtain license type from the token");
			}
			await Channel.Add(new AuditAcitivity
			{
				Username = context.Principal.Identity.Name,
				LoginType = (ELoginType)loginType,
				LastActivity = DateTime.UtcNow,
				IpAddress = context.HttpContext.Connection.RemoteIpAddress.ToString(),
				UserAgent = context.Request.Headers["User-Agent"]
			});
		}
	}
}
