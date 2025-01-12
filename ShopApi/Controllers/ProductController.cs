using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using ShopApi.Interfaces.Repositories;
using ShopApi.Models;

namespace ShopApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ProductController : ShopController
    {
        private IProductRepository ProductRepository { get; set; }
        public ProductController(ShopDbContext context, ILogger<ProductController> logger, IProductRepository productRepository) : base(context, logger)
        {
            ProductRepository = productRepository;
        }

        [HttpPost]
        public async Task<ActionResult> InitProductFromCSV()
        {
            string filePath = @"F:\Bartek\Projekty\Inwentaryzacja\BarcodeDatabase\OpenFoodFacts\CSV\en.openfoodfacts.org.products.csv";

            var result = await ProductRepository.InitProductFromCSV(filePath);

            if (result.IsNullOrEmpty())
                Ok("Inicjalizacja produktów z pliku csv zakończona pomyślnie");
            else NotFound($"Wystąpił problem podczas inicjalizacji produktów: {result}");


            return Ok();
        }
    }
}
