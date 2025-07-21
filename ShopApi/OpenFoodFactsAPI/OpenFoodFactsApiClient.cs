using ShopApi.OpenFoodFactsAPI.Model;

namespace ShopApi.OpenFoodFactsAPI
{
	public class OpenFoodFactsApiClient : BaseApiClient, IOpenFoodFactsApiClient
	{
		private readonly ILogger<OpenFoodFactsApiClient> _logger;
		private const string BaseUrl = "https://world.openfoodfacts.org/api/v3";

		public OpenFoodFactsApiClient(HttpClient httpClient, ILogger<OpenFoodFactsApiClient> logger)
			: base(httpClient)
		{
			_logger = logger ?? throw new ArgumentNullException(nameof(logger));
			_httpClient.BaseAddress = new Uri(BaseUrl);
		}

		/// <summary>
		/// Gets product information by barcode
		/// </summary>
		/// <param name="barcode">Product barcode</param>
		/// <returns>Product information</returns>
		public async Task<OpenFoodFactsResponse> GetProductByBarcodeAsync(string barcode)
		{
			try
			{
				return await GetAsync<OpenFoodFactsResponse>($"/product/{barcode}.json");
			}
			catch (ApiException ex)
			{
				_logger.LogError(ex, $"Error fetching product with barcode {barcode}");
				throw;
			}
		}
	}
}
