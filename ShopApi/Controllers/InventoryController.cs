using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ShopApi.Models;
using ShopApi.Models.Database;

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
    }
}
