using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using ShopApi.Extensions;
using ShopApi.Models;
using ShopApi.Models.Database;
using ShopApi.Models.TransferObject;
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
            var inventories = await Context.Inventories.Include(i => i.CreatedByUser).Include(w => w.InventoryStatus).Where(w => w.InventoryStatus.Code != "FIN").OrderByDescending(w => w.CreatedAt).ToListAsync();
            return Ok(inventories);
        }

        [HttpGet]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<Inventory>> GetInventoryById([FromQuery] int inventoryId)
        {
            var inventory = await Context.Inventories.Include(i => i.CreatedByUser).Include(i => i.InventoryStatus).FirstOrDefaultAsync(i => i.Id == inventoryId);
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
            if (inventoryPosition.ProductId == 0)
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

            commonInventoryPosition.ModifiedByUserId = null;
            commonInventoryPosition.UserId = id;
            var unit = commonInventoryPosition.Unit;
            commonInventoryPosition.Unit = null;

            await Context.CommonInventoryPositions.AddAsync(commonInventoryPosition);
            await Context.SaveChangesAsync();

            if(unit == null)
                commonInventoryPosition.Unit = await Context.Units.FirstOrDefaultAsync(u => u.Id == commonInventoryPosition.UnitId);
            else
                commonInventoryPosition.Unit = unit;
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

            if (searchingPosition == null)
                return NotFound("Nie znaleziono pozycji inwentaryzacji do edycji.");
            else
            {
                var product = inventoryPosition.Product;
                searchingPosition.Product = null;
                searchingPosition.Quantity = inventoryPosition.Quantity;
                searchingPosition.Price = inventoryPosition.Price;
                searchingPosition.ModifiedByUserId = id;
                searchingPosition.ModificationDate = DateTime.Now;
                Context.InventoryPositions.Update(searchingPosition);
                await Context.SaveChangesAsync();
                searchingPosition.Product = product;
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

            if (commonInventoryPosition.Unit == null)
                commonInventoryPosition.Unit = await Context.Units.FirstOrDefaultAsync(u => u.Id == commonInventoryPosition.UnitId);

            if (searchingPosition == null)
                return NotFound("Nie znaleziono pozycji inwentaryzacji do edycji.");
            else
            {
                var unit = commonInventoryPosition.Unit;
                searchingPosition.Quantity = commonInventoryPosition.Quantity;
                searchingPosition.Price = commonInventoryPosition.Price;
                searchingPosition.UnitId = commonInventoryPosition.UnitId;
                searchingPosition.ModifiedByUserId = id;
                searchingPosition.ModificationDate = DateTime.Now;
                Context.CommonInventoryPositions.Update(searchingPosition);
                await Context.SaveChangesAsync();
                searchingPosition.Unit = unit;
                return Ok(searchingPosition);
            }
        }

        [HttpPost]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<int>> DeleteInventoryPosition([FromBody] InventoryPosition inventoryPosition)
        {
            int id = HttpContext.GetShopUserId();
            if (inventoryPosition.InventoryId == 0)
                return BadRequest("Nie wybrano inwentaryzacji.");
            if (inventoryPosition.ProductId == 0)
                return BadRequest("Nie wybrano produktu.");

            var searchingPosition = await Context.InventoryPositions.FirstOrDefaultAsync(ip => ip.Id == inventoryPosition.Id);

            if (searchingPosition == null)
                return NotFound("Nie znaleziono pozycji inwentaryzacji do usunięcia.");
            else
            {
                searchingPosition.Product = null;
                searchingPosition.ModifiedByUserId = id;
                searchingPosition.ModificationDate = DateTime.Now;
                searchingPosition.IsDeleted = 1;
                Context.InventoryPositions.Update(searchingPosition);
                await Context.SaveChangesAsync();
                return Ok(searchingPosition.Id);
            }
        }

        [HttpPost]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<int>> DeleteCommonInventoryPosition([FromBody] CommonInventoryPosition commonInventoryPosition)
        {
            int id = HttpContext.GetShopUserId();
            if (commonInventoryPosition.InventoryId == 0)
                return BadRequest("Nie wybrano inwentaryzacji.");
            if (string.IsNullOrEmpty(commonInventoryPosition.ProductName) || commonInventoryPosition.UnitId == 0 || commonInventoryPosition.Price < 0.0 || commonInventoryPosition.Quantity < 0.0)
                return BadRequest("Usuwana pozycja zawiera niuzupełnione dane");

            var searchingPosition = await Context.CommonInventoryPositions.FirstOrDefaultAsync(ip => ip.Id == commonInventoryPosition.Id);

            if (searchingPosition == null)
                return NotFound("Nie znaleziono pozycji inwentaryzacji do usunięcia.");
            else
            {
                searchingPosition.Unit = null;
                searchingPosition.ModifiedByUserId = id;
                searchingPosition.ModificationDate = DateTime.Now;
                searchingPosition.IsDeleted = 1;
                Context.CommonInventoryPositions.Update(searchingPosition);
                await Context.SaveChangesAsync();
                return Ok(searchingPosition.Id);
            }
        }

        [HttpGet]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<List<InventoryPosition>>> GetAllInventoryPositions([FromQuery] int inventoryId)
        {
            var inventoryPositions = await Context.InventoryPositions.Where(w => w.InventoryId == inventoryId && w.IsDeleted != 1)
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
            if (userId == null)
                userId = HttpContext.GetShopUserId();
            var inventoryPositions = await Context.InventoryPositions.Where(w => w.InventoryId == inventoryId && w.UserId == userId && w.IsDeleted != 1)
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
            var inventoryPositions = await Context.CommonInventoryPositions.Where(w => w.InventoryId == inventoryId && w.IsDeleted != 1).Include(w => w.Unit).ToListAsync();
            return inventoryPositions.IsNullOrEmpty() ? NotFound("Nie znaleziono listy pozycji dla wybranej inwentaryzacji") : Ok(inventoryPositions);
        }

        [HttpGet]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<List<CommonInventoryPosition>>> GetAllCommonInventoryPositionsForUser([FromQuery] int inventoryId, [FromQuery] int? userId = null)
        {
            if (userId == null)
                userId = HttpContext.GetShopUserId();
            var inventoryPositions = await Context.CommonInventoryPositions.Where(w => w.InventoryId == inventoryId && w.UserId == userId && w.IsDeleted != 1).Include(w => w.Unit).ToListAsync();
            return inventoryPositions.IsNullOrEmpty() ? NotFound("Nie znaleziono listy pozycji dla wybranej inwentaryzacji") : Ok(inventoryPositions);
        }

        [HttpGet]
        [Route("[action]")]
        [Authorize(Roles = "ADM,USR")]
        public async Task<ActionResult<List<SummaryInventoryPosition>>> GetAllSummaryPositions([FromQuery] int inventoryId)
        {
            var inventoryPositions = await Context.InventoryPositions.Where(w => w.InventoryId == inventoryId && w.IsDeleted != 1).Include(w => w.Product)
                .ThenInclude(p => p.Unit)
                .GroupBy(ip => new { ip.ProductId, ip.Price })
                .Select(g => new
                {
                    ProductId = g.Key.ProductId,
                    Price = g.Key.Price,
                    Quantity = g.Sum(x => x.Quantity),
                    Product = g.First().Product,
                    LatestDate = g.Max(x => x.ModificationDate ?? x.ScanDate)
                }).ToListAsync();
            var commonInventoryPositions = await Context.CommonInventoryPositions.Where(w => w.InventoryId == inventoryId && w.IsDeleted != 1).Include(w => w.Unit).ToListAsync();

            List<SummaryInventoryPosition> summaryInventoryPositions = new List<SummaryInventoryPosition>();
            foreach (var inventoryPosition in inventoryPositions)
            {
                var summaryInventoryPosition = new SummaryInventoryPosition()
                {
                    ProductName = inventoryPosition.Product.ProductName(),
                    Quantity = inventoryPosition.Quantity,
                    Price = inventoryPosition.Price,
                    Unit = inventoryPosition.Product?.Unit?.Name ?? "",
                    DateOfScanOrModification = inventoryPosition.LatestDate
                };
                summaryInventoryPositions.Add(summaryInventoryPosition);
            }

            foreach (CommonInventoryPosition commonInventoryPosition in commonInventoryPositions)
            {
                var summaryInventoryPosition = new SummaryInventoryPosition()
                {
                    ProductName = commonInventoryPosition.ProductName,
                    Quantity = commonInventoryPosition.Quantity,
                    Price = commonInventoryPosition.Price,
                    Unit = commonInventoryPosition.Unit?.Name ?? "",
                    DateOfScanOrModification = (DateTime)(commonInventoryPosition.ModificationDate != null ? commonInventoryPosition.ModificationDate : commonInventoryPosition.ScanDate)
                };
                summaryInventoryPositions.Add(summaryInventoryPosition);
            }
            if (summaryInventoryPositions.IsNullOrEmpty())
                return NotFound("Nie znaleziono pozycji dla wybranej inwentaryzacji");

            return Ok(summaryInventoryPositions.OrderByDescending(w => w.DateOfScanOrModification));
        }
    }
}
