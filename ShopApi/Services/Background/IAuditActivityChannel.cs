using ShopApi.Models.Enums;

namespace ShopApi.Services.Background
{
	public interface IAuditActivityChannel
	{
		ValueTask Add(AuditAcitivity workItem);

		IAsyncEnumerable<AuditAcitivity> Events(CancellationToken cancellationToken);
	}
	public class AuditAcitivity
	{
		public string Username { get; set; } = default!;
		public ELoginType LoginType { get; set; }
		public string IpAddress { get; set; } = default!;
		public DateTime LastActivity { get; set; }
		public string UserAgent { get; set; } = default!;
	}
}
