using System.Text.Json.Serialization;

namespace ShopApi.OpenFoodFactsAPI.Model
{
	//public class OpenFoodFactsProduct
	//{
	//	[JsonPropertyName("_id")]
	//	public string Id { get; set; }

	//	[JsonPropertyName("product_name")]
	//	public string ProductName { get; set; }

	//	[JsonPropertyName("brands")]
	//	public string Brands { get; set; }

	//	[JsonPropertyName("quantity")]
	//	public string Quantity { get; set; }

	//	[JsonPropertyName("labels")]
	//	public string Labels { get; set; }

	//	[JsonPropertyName("image_url")]
	//	public string ImageUrl { get; set; }

	//	[JsonPropertyName("categories")]
	//	public string Categories { get; set; }

	//	// Add other properties as needed based on the API response
	//}
	public class OpenFoodFactsProduct
	{
		[JsonPropertyName("_id")]
		public string Id { get; set; }

		[JsonPropertyName("code")]
		public string Barcode { get; set; }

		[JsonPropertyName("product_name")]
		public string ProductName { get; set; }

		[JsonPropertyName("product_name_pl")]
		public string ProductNamePl { get; set; }

		[JsonPropertyName("brands")]
		public string Brands { get; set; }

		[JsonPropertyName("quantity")]
		public string Quantity { get; set; }

		[JsonPropertyName("labels")]
		public string Labels { get; set; }

		[JsonIgnore]
		public string ImageUrl
		{
			get
			{
				if (SelectedImages?.Front?.Display != null &&
					SelectedImages.Front.Display.ContainsKey("pl"))
				{
					return SelectedImages.Front.Display["pl"];
				}
				else if (SelectedImages?.Front?.Display != null &&
						SelectedImages.Front.Display.Any())
				{
					return SelectedImages.Front.Display.First().Value;
				}
				return null;
			}
		}

		[JsonPropertyName("categories")]
		public string Categories { get; set; }

		[JsonPropertyName("selected_images")]
		public SelectedImages SelectedImages { get; set; }

		// Method to get product name (Polish version preferred)
		//[JsonIgnore]
		//public string GetProductName()
		//{
		//	return !string.IsNullOrEmpty(ProductNamePl) ? ProductNamePl : ProductName;
		//}
	}

	public class SelectedImages
	{
		[JsonPropertyName("front")]
		public ImageTypes Front { get; set; }

		[JsonPropertyName("ingredients")]
		public ImageTypes Ingredients { get; set; }

		[JsonPropertyName("nutrition")]
		public ImageTypes Nutrition { get; set; }
	}

	public class ImageTypes
	{
		[JsonPropertyName("display")]
		public Dictionary<string, string> Display { get; set; }

		[JsonPropertyName("small")]
		public Dictionary<string, string> Small { get; set; }

		[JsonPropertyName("thumb")]
		public Dictionary<string, string> Thumb { get; set; }
	}
}
