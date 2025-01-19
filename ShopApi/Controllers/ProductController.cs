using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using ShopApi.Interfaces.Repositories;
using ShopApi.Models.Database;
using ShopApi.Models;
using Microsoft.EntityFrameworkCore;

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
        [Route("[action]")]
        public async Task<ActionResult> InitProductFromCSV()
        {
            string filePath = @"F:\Bartek\Projekty\Inwentaryzacja\BarcodeDatabase\OpenFoodFacts\CSV\en.openfoodfacts.org.products.csv";

            var result = await ProductRepository.InitProductFromCSV(filePath);

            if (result.IsNullOrEmpty())
                Ok("Inicjalizacja produktów z pliku csv zakończona pomyślnie");
            else NotFound($"Wystąpił problem podczas inicjalizacji produktów: {result}");


            return Ok();
        }
        [HttpGet]
        [Route("[action]")]
        public async Task<ActionResult> GetProductByBarcode([FromQuery] string barcode)
        {
            var listOfProduct = Context.Barcodes.Where(b => b.Code == barcode).Select(b => b.Product).ToList();
            if(listOfProduct.IsNullOrEmpty())
            {
                var product = Context.InitProducts.FirstOrDefault(ip => ip.Barcode == barcode);
                if(product == null) 
                    return NotFound("Nie znaleziono produktu z podanym kodem");
                else
                {
                    var productToAdd = new Product()
                    {
                        Name = product.Name,
                        Brand = product.Brand,
                        Label = product.Label,
                        Capacity = product.Capacity,
                        IsGeneral = false,
                        UnitId = Context.Units.FirstOrDefault(w => w.Code == "szt").Id
                    };
                    productToAdd.Barcodes.Add(new Barcode()
                    {
                        Code = product.Barcode
                    });
                    Context.Products.Add(productToAdd);
                    await Context.SaveChangesAsync();
                    listOfProduct = Context.Barcodes.Where(b => b.Code == barcode).Select(b => b.Product).ToList();
                    return listOfProduct.IsNullOrEmpty() ? NotFound("Nie znaleziono produktu z podanym kodem") : Ok(listOfProduct);
                }
            } else
                return Ok(listOfProduct);
        }
        [HttpPost]
        [Route("[action]")]
        public async Task<ActionResult> AddProduct([FromBody] Product product)
        {
            if(!product.IsGeneral)
            {
                var productVerify = Context.Products.Where(p => p.Barcodes.Any(b => !product.Barcodes.IsNullOrEmpty() && product.Barcodes.FirstOrDefault().Code == b.Code) && !p.IsGeneral);
                if (!productVerify.IsNullOrEmpty())
                    return BadRequest("Produkt o takim kodzie kreskowym jest już dodany");
            }
            
            Context.Products.Add(product);
            await Context.SaveChangesAsync();
            return Ok(product.Id);
        }
        [HttpGet]
        [Route("[action]")]
        public async Task<ActionResult> GetAllProducts()
        {
            var allProducts = await Context.Products.ToListAsync();
            return allProducts.IsNullOrEmpty() ? NotFound("Nie znaleziono produktów") : Ok(allProducts);
        }
    }
}
