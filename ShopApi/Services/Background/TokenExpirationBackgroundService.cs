using ShopApi.Models;
using ShopApi.Utilities;

namespace ShopApi.Services.Background
{
	public class TokenExpirationBackgroundService : BackgroundService
	{
		public IServiceProvider ServiceProvider { get; }
		public ILogger<TokenExpirationBackgroundService> Logger { get; }
		private TokenExpirationBackgroundServiceSettings Settings => ServiceProvider.GetSettings<TokenExpirationBackgroundServiceSettings>();

		public TokenExpirationBackgroundService(IServiceProvider serviceProvider, ILogger<TokenExpirationBackgroundService> logger)
		{
			ServiceProvider = serviceProvider;
			Logger = logger;
		}


		protected override async Task ExecuteAsync(CancellationToken stoppingToken)
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				await Task.Delay(TimeSpan.FromSeconds(Settings.IntervalSeconds), stoppingToken);
				using var scope = ServiceProvider.CreateScope();
				var tokenContext = scope.ServiceProvider.GetRequiredService<TokenDbContext>();
				var expiredTokens = tokenContext.ShopApiTokens.Where(token => token.ExpirationDate <= DateTime.UtcNow);
				tokenContext.RemoveRange(expiredTokens);
				await tokenContext.SaveChangesAsync(cancellationToken: stoppingToken);
			}
		}
	}
}
