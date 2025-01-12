using Microsoft.AspNetCore.Mvc;
using ShopApi.Models;

namespace ShopApi.Controllers
{
    public abstract class ShopController : ControllerBase
    {
        protected ILogger Logger { get; }
        protected ShopDbContext Context { get; }
        public ShopController(ShopDbContext context, ILogger logger)
        {
            Context = context;
            Logger = logger;
        }
    }
}
