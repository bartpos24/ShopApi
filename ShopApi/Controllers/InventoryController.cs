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
            var inventories = await Context.Inventories.ToListAsync();
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
		public async Task<ActionResult<int>> AddInventoryPosition([FromBody] InventoryPosition inventoryPosition)
		{
            if(inventoryPosition.InventoryId == 0)
                return BadRequest("Nie wybrano inwentaryzacji.");
            if(inventoryPosition.ProductId == 0)
                return BadRequest("Nie wybrano produktu.");

			await Context.InventoryPositions.AddAsync(inventoryPosition);
			await Context.SaveChangesAsync();
			return Ok(inventoryPosition.Id);
		}

		[HttpGet]
		[Route("[action]")]
		[Authorize(Roles = "ADM,USR")]
		public async Task<ActionResult<List<Inventory>>> GetAllInventoryPositions([FromQuery] int inventoryId)
		{
			var inventoryPositions = await Context.InventoryPositions.Where(w => w.InventoryId == inventoryId).ToListAsync();
			return inventoryPositions.IsNullOrEmpty() ? NotFound("Nie znaleziono pozycji dla wybranej inwentaryzacji") : Ok(inventoryPositions);
		}

		[HttpGet]
		[Route("[action]")]
		[Authorize(Roles = "ADM,USR")]
		public async Task<ActionResult<List<Inventory>>> GetAllInventoryPositionsForUser([FromQuery] int inventoryId, [FromQuery] int? userId = null)
		{
            if(userId == null)
                userId = HttpContext.GetShopUserId();
			var inventoryPositions = await Context.InventoryPositions.Where(w => w.InventoryId == inventoryId && w.UserId == userId).ToListAsync();
			return inventoryPositions.IsNullOrEmpty() ? NotFound("Nie znaleziono pozycji dla wybranej inwentaryzacji") : Ok(inventoryPositions);
		}
	}
}
