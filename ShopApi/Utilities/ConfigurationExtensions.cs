using Microsoft.Extensions.Options;

namespace ShopApi.Utilities
{
	public static class ConfigurationExtensions
	{
		public static T GetConfig<T>(this IConfiguration config, string section) where T : new()
		{
			var settings = new T();
			config.GetSection(section).Bind(settings);
			return settings;
		}
		public static T GetSettings<T>(this IServiceProvider serviceProvider) where T : class, new()
		{
			using var scope = serviceProvider.CreateScope();
			return scope.ServiceProvider.GetRequiredService<IOptionsSnapshot<T>>().Value;
		}
	}
}
