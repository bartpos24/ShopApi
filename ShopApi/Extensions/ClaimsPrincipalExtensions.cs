using ShopApi.Models.Enums;
using System.Security.Claims;

namespace ShopApi.Extensions
{
	public static class ClaimsPrincipalExtensions
	{
		public static string ShopLoginClaimsKey => "login_type";
		private static string? GetShopClaim(this IEnumerable<Claim> claims, string claimType) => claims.FirstOrDefault(c => c.Type == claimType)?.Value;
		public static (bool isNumber, int id, string original) ShopUserId(this ClaimsPrincipal user)
		{
			var uid = user.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value;
			return (isNumber: int.TryParse(uid, out var id), id: id, original: uid);
		}

		public static ELoginType? ShopLoginType(this ClaimsPrincipal user) => user.Claims.ShopLoginType();
		public static ELoginType? ShopLoginType(this IEnumerable<Claim> claims)
		{
			var licenseClaim = claims.FirstOrDefault(c => c.Type == ShopLoginClaimsKey);
			if (Enum.TryParse<ELoginType>(licenseClaim?.Value, out var licenseType))
				return licenseType;
			else
				return null;
		}
	}
}
