using ShopApi.Models.Database;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

namespace ShopApi.Extensions
{
    public static class ProductExtensions
    {
        public static string ProductName(this Product? product)
        {
            if (product == null)
                return string.Empty;

            string result;

            // Step 1: Handle Brand and Name
            if (!string.IsNullOrEmpty(product.Name) && !string.IsNullOrEmpty(product.Brand) && product.Name.Contains(product.Brand))
                result = product.Name;
            else if (!string.IsNullOrEmpty(product.Brand) && !string.IsNullOrEmpty(product.Name))
                result = $"{product.Brand} {product.Name}";
            else if (!string.IsNullOrEmpty(product.Name))
                result = product.Name;
            else if (!string.IsNullOrEmpty(product.Brand))
                result = product.Brand;
            else
                result = string.Empty;

            // Step 2: Handle Capacity
            if (string.IsNullOrEmpty(product.Capacity))
                return result.Trim();

            // Extract numeric value from capacity (handles both comma and dot as decimal separator)
            var capacityNumberMatch = Regex.Match(product.Capacity, @"(\d+[.,]?\d*)");

            if (!capacityNumberMatch.Success)
            {
                // No number found in capacity, just append it
                result = $"{result} {product.Capacity}";
                return result.Trim();
            }

            string capacityNumber = capacityNumberMatch.Value;

            // Normalize the number for comparison (replace comma with dot)
            string normalizedCapacityNumber = capacityNumber.Replace(',', '.');

            // Check if product.Name contains the full capacity string (e.g., "850 ml")
            if (result.Contains(product.Capacity))
            {
                // Don't add capacity again, it's already there
                return result.Trim();
            }

            // Check if the number appears after a whitespace in the result (e.g., "Coca-cola 850" or "Muszynianka 1,5")
            // Match the number with either comma or dot, surrounded by word boundaries or whitespace
            string pattern = @"\s+" + Regex.Escape(capacityNumber).Replace(@"\.", @"[.,]").Replace(@"\,", @"[.,]");
            var nameNumberMatch = Regex.Match(result, pattern);

            if (nameNumberMatch.Success)
            {
                // Remove the number with the preceding whitespace and add full capacity
                result = Regex.Replace(result, pattern, " ");
                result = $"{result} {product.Capacity}";
            }
            else
            {
                // Number not found after whitespace or not found at all, just append capacity
                result = $"{result} {product.Capacity}";
            }

            return result.Trim();
        }
    }
}
