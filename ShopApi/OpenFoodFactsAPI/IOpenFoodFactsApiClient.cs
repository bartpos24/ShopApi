using ShopApi.OpenFoodFactsAPI.Model;

namespace ShopApi.OpenFoodFactsAPI
{
	public interface IOpenFoodFactsApiClient
	{
		Task<OpenFoodFactsResponse> GetProductByBarcodeAsync(string barcode);
	}
}
