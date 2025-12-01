using Microsoft.AspNetCore.Http;

namespace ShopApi.Security
{
	public static class TokenExtensions
	{
		private static string ShopIdKey => "ShopUserIdKey";
		internal static void SetShopUserId(this HttpContext context, int userId) => context.Items.Add(ShopIdKey, userId);
		public static int GetShopUserId(this HttpContext context) => (int)context.Items[ShopIdKey];
	}
}
