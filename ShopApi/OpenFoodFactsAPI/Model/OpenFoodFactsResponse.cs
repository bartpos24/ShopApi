using System.Text.Json.Serialization;

namespace ShopApi.OpenFoodFactsAPI.Model
{
	public class OpenFoodFactsResponse
	{
		[JsonPropertyName("code")]
		public string Code { get; set; }

		[JsonPropertyName("status")]
		public int Status { get; set; }

		[JsonPropertyName("status_verbose")]
		public string StatusVerbose { get; set; }

		[JsonPropertyName("product")]
		public OpenFoodFactsProduct Product { get; set; }
	}
}
