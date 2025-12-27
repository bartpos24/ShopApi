using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using ShopApi.Interfaces.Repositories;
using ShopApi.Models.Database;
using ShopApi.Models;
using Microsoft.EntityFrameworkCore;
using ShopApi.OpenFoodFactsAPI.Service;
using ShopApi.OpenFoodFactsAPI;
using ShopApi.OpenFoodFactsAPI.Model;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;

namespace ShopApi.Controllers
{
	[ApiController]
	[Route("api/[controller]")]
	public class ProductController : ShopController
	{
		private IProductRepository ProductRepository { get; set; }
		private readonly IOpenFoodFactsService openFoodFactsService;
		public ProductController(ShopDbContext context, ILogger<ProductController> logger, IProductRepository productRepository, IOpenFoodFactsService _openFoodFactsService) : base(context, logger)
		{
			ProductRepository = productRepository;
			openFoodFactsService = _openFoodFactsService;
		}

		[HttpPost]
		[Route("[action]")]
		[Authorize(Roles = "ADM,USR")]
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
		[Authorize(Roles = "ADM,USR")]
		public async Task TestApiDirectly()
		{
			using var client = new HttpClient();
			client.DefaultRequestHeaders.UserAgent.ParseAdd("TestApp/1.0");
			var response = await client.GetAsync("https://world.openfoodfacts.org/api/v0/product/5906340630011.json");
			var content = await response.Content.ReadAsStringAsync();

			try
			{
				var jsonOptions = new JsonSerializerOptions
				{
					PropertyNameCaseInsensitive = true,
					PropertyNamingPolicy = JsonNamingPolicy.CamelCase
				};

				var openFoodFactsResponse = JsonSerializer.Deserialize<OpenFoodFactsResponse>(content, jsonOptions);

				var product = openFoodFactsResponse?.Product;

			}
			catch (JsonException ex)
			{
				Console.WriteLine($"JSON parsing error: {ex.Message}");
				Console.WriteLine($"JSON parsing error: {ex.Message}");
			}
		}

		[HttpGet]
		[Route("[action]")]
		[Authorize(Roles = "ADM,USR")]
		public async Task<ActionResult<Product>> GetProductFromOpenFoodFacts([FromQuery] string barcode)
		{
			try
			{
				var product = await openFoodFactsService.GetProductByBarcodeAsync(barcode);

				if (product == null)
				{
					return NotFound($"Product with barcode {barcode} not found in OpenFoodFacts database");
				}

				// Optionally save to local database
				if (product.UnitId == 0)
				{
					var defaultUnit = await Context.Units.FirstOrDefaultAsync(u => u.Code == "szt");
					if (defaultUnit != null)
					{
						product.UnitId = defaultUnit.Id;
					}
				}

				//if(await Context.Barcodes.Any(b => product.Barcodes.Contains(pb => pb.)))
				//Context.Products.Add(product);
				//await Context.SaveChangesAsync();

				return Ok(product);
			}
			catch (ApiException ex)
			{
				Logger.LogError(ex, $"API error occurred while fetching product with barcode {barcode}");
				return StatusCode(500, $"Error communicating with OpenFoodFacts API: {ex.Message}");
			}
			catch (Exception ex)
			{
				Logger.LogError(ex, $"Error occurred while processing product with barcode {barcode}");
				return StatusCode(500, "An error occurred while processing your request");
			}
		}

		[HttpGet]
		[Route("[action]")]
		[Authorize(Roles = "ADM,USR")]
		public async Task<ActionResult<List<Product>>> GetProductByBarcode([FromQuery] string barcode)
		{
			var productIds = await Context.Barcodes.Where(b => b.Code == barcode).Select(b => b.ProductId).ToListAsync();
			var listOfProduct = await Context.Products.Where(p => productIds.Contains(p.Id)).Include(u => u.Unit).Include(b => b.Barcodes).ToListAsync();
			if (listOfProduct.IsNullOrEmpty())
			{
				var product = await Context.InitProducts.FirstOrDefaultAsync(ip => ip.Barcode == barcode);
				if (product == null)
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
					await Context.Products.AddAsync(productToAdd);
					await Context.SaveChangesAsync();
					var productBarcode = new Barcode
					{
						Code = product.Barcode,
						ProductId = productToAdd.Id
					};
					await Context.Barcodes.AddAsync(productBarcode);
					await Context.SaveChangesAsync();
					listOfProduct.Add(await Context.Products.Include(u => u.Unit).Include(b => b.Barcodes).FirstOrDefaultAsync(w => w.Id == productToAdd.Id));
					return listOfProduct.IsNullOrEmpty() ? NotFound("Nie znaleziono produktu z podanym kodem") : Ok(listOfProduct);
				}
			}
			else
				return Ok(listOfProduct);
		}
		[HttpPost]
		[Route("[action]")]
		[Authorize(Roles = "ADM,USR")]
		public async Task<ActionResult<int>> AddProduct([FromBody] Product product)
		{
			if (!product.IsGeneral)
			{
				var productVerify = Context.Products.Where(p => p.Barcodes.Any(b => !product.Barcodes.IsNullOrEmpty() && product.Barcodes.FirstOrDefault().Code == b.Code) && !p.IsGeneral);
				if (!productVerify.IsNullOrEmpty())
					return BadRequest("Produkt o takim kodzie kreskowym jest już dodany");
			}

			Context.Products.Add(product);
			await Context.SaveChangesAsync();
			return Ok(product.Id);
		}
        [HttpPost]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<int>> AddEditProduct([FromBody] Product product, [FromQuery] string barcode)
        {
			if(product.Id > 0)
			{
				var productToEdit = await Context.Products.FirstOrDefaultAsync(w => w.Id == product.Id);
				if (productToEdit == null)
					return NotFound("Nie znaleziono produktu do edycji");
				productToEdit.Brand = product.Brand;
				productToEdit.Name = product.Name;
				productToEdit.Capacity = product.Capacity;
				productToEdit.UnitId = product.UnitId;
				var result = Context.Products.Update(productToEdit);
				await Context.SaveChangesAsync();
				return Ok(productToEdit.Id);
			} else
			{
				if (string.IsNullOrEmpty(barcode))
					return NotFound("Nie podano kodu kreskowego produktu");
				await Context.Products.AddAsync(product);
                await Context.SaveChangesAsync();
                var productBarcode = new Barcode
                {
                    Code = barcode,
                    ProductId = product.Id
                };
                await Context.Barcodes.AddAsync(productBarcode);
                await Context.SaveChangesAsync();
				return Ok(product.Id);
            }
        }
        [HttpGet]
		[Route("[action]")]
		[Authorize(Roles = "ADM,USR")]
		public async Task<ActionResult<List<Product>>> GetAllProducts()
		{
			var allProducts = await Context.Products.ToListAsync();
			return allProducts.IsNullOrEmpty() ? NotFound("Nie znaleziono produktów") : Ok(allProducts);
		}
		[HttpGet]
		[Route("[action]")]
		[Authorize(Roles = "ADM,USR")]
		public async Task<ActionResult<List<Product>>> GetAllProductsTestOpenApiGenerate()
		{
			var allProducts = await Context.Products.ToListAsync();
			return allProducts.IsNullOrEmpty() ? NotFound("Nie znaleziono produktów") : Ok(allProducts);
		}

        [HttpGet]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
		public async Task<ActionResult<List<ProductUnit>>> GetAllUnits()
		{
			var allUnits = await Context.Units.ToListAsync();
			return allUnits.IsNullOrEmpty() ? NotFound("Nie znaleziono listy jednostek") : Ok(allUnits);
        }
    }
}
