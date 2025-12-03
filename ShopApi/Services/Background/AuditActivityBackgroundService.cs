using Microsoft.EntityFrameworkCore;
using ShopApi.Models;

namespace ShopApi.Services.Background
{
	class AuditActivityBackgroundService : BackgroundService
	{
		private IServiceProvider ServiceProvider { get; }
		private ILogger<AuditActivityBackgroundService> Logger { get; }
		private IAuditActivityChannel AuditActivityChannel { get; }

		public AuditActivityBackgroundService(IServiceProvider serviceProvider, ILogger<AuditActivityBackgroundService> logger, IAuditActivityChannel auditActivityChannel)
		{
			Logger = logger;
			ServiceProvider = serviceProvider;
			AuditActivityChannel = auditActivityChannel;
		}

		protected override async Task ExecuteAsync(CancellationToken stoppingToken)
		{
			await foreach (var auditEvent in AuditActivityChannel.Events(stoppingToken))
			{
				await HandleAuditActivityEvent(auditEvent);
			}
		}
		private async Task HandleAuditActivityEvent(AuditAcitivity data)
		{
			try
			{
				using var scope = ServiceProvider.CreateScope();
				var tokenContext = scope.ServiceProvider.GetRequiredService<TokenDbContext>();

				var token = await tokenContext.ShopApiTokens.FirstOrDefaultAsync(t => t.Username == data.Username && t.LoginType == data.LoginType);

				if (token == null)
					return;

				token.LastActivity = new UserActivity
				{
					IpAddress = data.IpAddress,
					LastActivity = data.LastActivity,
					UserAgent = data.UserAgent
				};

				await tokenContext.SaveChangesAsync();
			}
			catch (Exception ex)
			{
				Logger.LogWarning(ex, $"Can't audit the event {data.IpAddress} {data.LastActivity}  {data.UserAgent} for the user {data.Username} {data.LoginType}");
			}


		}

	}
}
