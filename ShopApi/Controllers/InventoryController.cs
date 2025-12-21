using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using ShopApi.Models;
using ShopApi.Models.Database;
using ShopApi.Security;

namespace ShopApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class InventoryController : ShopController
    {
        public InventoryController(ShopDbContext context, ILogger<InventoryController> logger) : base(context, logger)
        {
        }

        [HttpGet]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<List<Inventory>>> GetAllInventories()
        {
            var inventories = await Context.Inventories.Include(i => i.CreatedByUser).Include(w => w.InventoryStatus).ToListAsync();
            return Ok(inventories);
        }

        [HttpGet]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<Inventory>> GetInventoryById([FromQuery] int inventoryId)
        {
            var inventory = await Context.Inventories.FirstOrDefaultAsync(i => i.Id == inventoryId);
            return inventory != null ? Ok(inventory) : NotFound("Nie znaleziono inwentaryzacji o podanym ID");
        }

		[HttpPost]
		[Route("[action]")]
		[Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<int>> CreateInventory([FromBody] Inventory inventory)
        {
            int id = HttpContext.GetShopUserId();
			inventory.CreatedAt = DateTime.Now;
            inventory.CreatedByUserId = id;
            inventory.StartDate = DateTime.Now;
            var status = await Context.InventoryStatus.FirstOrDefaultAsync(s => s.Code == "ACT");
			if (status is null)
			{
				NotFound("Nie znaleziono statusu inwentaryzacji");
			}
			inventory.InventoryStatusId = status!.Id;
			await Context.Inventories.AddAsync(inventory);
            await Context.SaveChangesAsync();
            return Ok(inventory.Id);
		}

		[HttpPost]
		[Route("[action]")]
		[Authorize(Roles = "ADM,USR")]
		public async Task<ActionResult<InventoryPosition>> AddInventoryPosition([FromBody] InventoryPosition inventoryPosition)
		{
            int id = HttpContext.GetShopUserId();
            if (inventoryPosition.InventoryId == 0)
                return BadRequest("Nie wybrano inwentaryzacji.");
            if(inventoryPosition.ProductId == 0)
                return BadRequest("Nie wybrano produktu.");

            inventoryPosition.UserId = id;
            var product = inventoryPosition.Product;
            inventoryPosition.Product = null;

            await Context.InventoryPositions.AddAsync(inventoryPosition);
            await Context.SaveChangesAsync();

            inventoryPosition.Product = product;
            return Ok(inventoryPosition);
		}

        [HttpPost]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<CommonInventoryPosition>> AddCommonInventoryPosition([FromBody] CommonInventoryPosition commonInventoryPosition)
        {
            int id = HttpContext.GetShopUserId();
            if (commonInventoryPosition.InventoryId == 0)
                return BadRequest("Nie wybrano inwentaryzacji.");
            if (string.IsNullOrEmpty(commonInventoryPosition.ProductName) || commonInventoryPosition.UnitId == 0 || commonInventoryPosition.Price < 0.0 || commonInventoryPosition.Quantity < 0.0)
                return BadRequest("Dodawana pozycja zawiera niuzupełnione dane");

            commonInventoryPosition.UserId = id;

            await Context.CommonInventoryPositions.AddAsync(commonInventoryPosition);
            await Context.SaveChangesAsync();
            return Ok(commonInventoryPosition);
        }

        [HttpPost]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<InventoryPosition>> EditInventoryPosition([FromBody] InventoryPosition inventoryPosition)
        {
            int id = HttpContext.GetShopUserId();
            if (inventoryPosition.InventoryId == 0)
                return BadRequest("Nie wybrano inwentaryzacji.");
            if (inventoryPosition.ProductId == 0)
                return BadRequest("Nie wybrano produktu.");

            var searchingPosition = await Context.InventoryPositions.FirstOrDefaultAsync(ip => ip.Id == inventoryPosition.Id);

            if(searchingPosition == null)
                return NotFound("Nie znaleziono pozycji inwentaryzacji do edycji.");
            else
            {
                searchingPosition.Quantity = inventoryPosition.Quantity;
                searchingPosition.Price = inventoryPosition.Price;
                searchingPosition.ModifiedByUserId = id;
                Context.InventoryPositions.Update(searchingPosition);
                await Context.SaveChangesAsync();
                return Ok(searchingPosition);
            }
        }

        [HttpPost]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<CommonInventoryPosition>> EditCommonInventoryPosition([FromBody] CommonInventoryPosition commonInventoryPosition)
        {
            int id = HttpContext.GetShopUserId();
            if (commonInventoryPosition.InventoryId == 0)
                return BadRequest("Nie wybrano inwentaryzacji.");
            if (string.IsNullOrEmpty(commonInventoryPosition.ProductName) || commonInventoryPosition.UnitId == 0 || commonInventoryPosition.Price < 0.0 || commonInventoryPosition.Quantity < 0.0)
                return BadRequest("Edytowana pozycja zawiera niuzupełnione dane");

            var searchingPosition = await Context.CommonInventoryPositions.FirstOrDefaultAsync(ip => ip.Id == commonInventoryPosition.Id);

            if(searchingPosition == null)
                return NotFound("Nie znaleziono pozycji inwentaryzacji do edycji.");
            else
            {
                searchingPosition.Quantity = commonInventoryPosition.Quantity;
                searchingPosition.Price = commonInventoryPosition.Price;
                searchingPosition.ModifiedByUserId = id;
                Context.CommonInventoryPositions.Update(searchingPosition);
                await Context.SaveChangesAsync();
                return Ok(searchingPosition);
            }
        }

        [HttpGet]
		[Route("[action]")]
		[Authorize(Roles = "ADM,USR")]
		public async Task<ActionResult<List<InventoryPosition>>> GetAllInventoryPositions([FromQuery] int inventoryId)
		{
			var inventoryPositions = await Context.InventoryPositions.Where(w => w.InventoryId == inventoryId)
                .Include(w => w.Product).ThenInclude(w => w.Unit)
                .Include(w => w.Product).ThenInclude(w => w.Barcodes)
                .ToListAsync();
            return inventoryPositions.IsNullOrEmpty() ? NotFound("Nie znaleziono listy pozycji dla wybranej inwentaryzacji") : Ok(inventoryPositions);
		}

		[HttpGet]
		[Route("[action]")]
		[Authorize(Roles = "ADM,USR")]
		public async Task<ActionResult<List<InventoryPosition>>> GetAllInventoryPositionsForUser([FromQuery] int inventoryId, [FromQuery] int? userId = null)
		{
            if(userId == null)
                userId = HttpContext.GetShopUserId();
			var inventoryPositions = await Context.InventoryPositions.Where(w => w.InventoryId == inventoryId && w.UserId == userId)
                .Include(w => w.Product).ThenInclude(w => w.Unit)
                .Include(w => w.Product).ThenInclude(w => w.Barcodes)
                .ToListAsync();
			return inventoryPositions.IsNullOrEmpty() ? NotFound("Nie znaleziono listy pozycji dla wybranej inwentaryzacji") : Ok(inventoryPositions);
		}

        [HttpGet]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<List<CommonInventoryPosition>>> GetAllCommonInventoryPositions([FromQuery] int inventoryId)
        {
            var inventoryPositions = await Context.CommonInventoryPositions.Where(w => w.InventoryId == inventoryId).Include(w => w.Unit).ToListAsync();
            return inventoryPositions.IsNullOrEmpty() ? NotFound("Nie znaleziono listy pozycji dla wybranej inwentaryzacji") : Ok(inventoryPositions);
        }

        [HttpGet]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<List<CommonInventoryPosition>>> GetAllCommonInventoryPositionsForUser([FromQuery] int inventoryId, [FromQuery] int? userId = null)
        {
            if (userId == null)
                userId = HttpContext.GetShopUserId();
            var inventoryPositions = await Context.CommonInventoryPositions.Where(w => w.InventoryId == inventoryId && w.UserId == userId).Include(w => w.Unit).ToListAsync();
            return inventoryPositions.IsNullOrEmpty() ? NotFound("Nie znaleziono listy pozycji dla wybranej inwentaryzacji") : Ok(inventoryPositions);
        }
    }
}
