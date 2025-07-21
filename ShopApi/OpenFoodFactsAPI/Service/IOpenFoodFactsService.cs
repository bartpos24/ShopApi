using ShopApi.Models.Database;

namespace ShopApi.OpenFoodFactsAPI.Service
{
	public interface IOpenFoodFactsService
	{
		Task<Product> GetProductByBarcodeAsync(string barcode);
	}
}
