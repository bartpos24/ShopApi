using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace ShopApi.Services
{
	public class AuditActivityChannel : IAuditActivityChannel
	{
		private ILogger<AuditActivityChannel> Logger { get; }
		private Channel<AuditAcitivity> AuditItemsChannel { get; } = Channel.CreateUnbounded<AuditAcitivity>();
		public AuditActivityChannel(ILogger<AuditActivityChannel> logger)
		{
			Logger = logger;
		}
		public async ValueTask Add(AuditAcitivity workItem)
		{
			await AuditItemsChannel.Writer.WriteAsync(workItem);
		}

		public async IAsyncEnumerable<AuditAcitivity> Events([EnumeratorCancellation] CancellationToken cancellationToken)
		{
			var reader = AuditItemsChannel.Reader;
			while (await reader.WaitToReadAsync(cancellationToken))
			{
				if (cancellationToken.IsCancellationRequested)
					yield break;

				while (reader.TryRead(out AuditAcitivity item) && !cancellationToken.IsCancellationRequested)
					yield return item;
			}
		}
	}
}
