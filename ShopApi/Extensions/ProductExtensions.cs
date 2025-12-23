using ShopApi.Models.Database;
using System.Runtime.CompilerServices;

namespace ShopApi.Extensions
{
    public static class ProductExtensions
    {
        public static string ProductName(this Product? product)
        {
            if (product == null)
                return string.Empty;

            string result;

            if (product.Name.Contains(product.Brand))
                result = product.Name;
            else
                result = $"{product.Brand} {product.Name}";

            //Uzupelnic sprawdzenie pojemnosci w nazwie produktu
            //if(product.Name.Contains)

            result = $"{result} {product.Capacity}";
            return result;
        }

    }
}
