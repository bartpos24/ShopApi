using ShopApi.Models.Database;

namespace ShopApi.OpenFoodFactsAPI.Service
{
	public class OpenFoodFactsService : IOpenFoodFactsService
	{
		private readonly ILogger<OpenFoodFactsService> _logger;
		private readonly IOpenFoodFactsApiClient _apiClient;

		public OpenFoodFactsService(
			ILogger<OpenFoodFactsService> logger,
			IOpenFoodFactsApiClient apiClient)
		{
			_logger = logger ?? throw new ArgumentNullException(nameof(logger));
			_apiClient = apiClient ?? throw new ArgumentNullException(nameof(apiClient));
		}

		/// <summary>
		/// Fetches product information by barcode
		/// </summary>
		public async Task<Product> GetProductByBarcodeAsync(string barcode)
		{
			try
			{
				var response = await _apiClient.GetProductByBarcodeAsync(barcode);

				if (response.Status != 1 || response.Product == null)
				{
					_logger.LogWarning($"Product with barcode {barcode} not found. Status: {response.StatusVerbose}");
					return null;
				}

				// Map the API response to our domain model
				var product = new Product
				{
					Name = !string.IsNullOrEmpty(response.Product.ProductNamePl)
						? response.Product.ProductNamePl
						: response.Product.ProductName,
					Brand = response.Product.Brands,
					Capacity = response.Product.Quantity,
					Label = response.Product.Labels,
					IsGeneral = false,
					Barcodes = new System.Collections.Generic.List<Barcode>
					{
						new Barcode { Code = barcode }
					}
				};

				return product;
			}
			catch (ApiException ex)
			{
				_logger.LogError(ex, $"API exception when fetching product with barcode {barcode}");
				throw;
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, $"Unexpected error when fetching product with barcode {barcode}");
				throw;
			}
		}
	}
}
