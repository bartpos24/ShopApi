using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ShopApi.Interfaces.Services;
using ShopApi.Models;
using ShopApi.Models.TransferObject;
using ShopApi.Services;

namespace ShopApi.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class UserController : ShopController
	{
		public UserController(ShopDbContext context, ILogger<LoginController> logger) : base(context, logger)
		{
		}

		[HttpGet]
		[Route("[action]")]
		[Authorize(Roles = "ADM,USR")]
		public async Task<ActionResult<UserInfo>> GetUser([FromQuery] int idUser)
		{
			var user = await Context.Users
				.Include(u => u.RoleForUsers)
				.ThenInclude(ru => ru.UserRole)
				.Select(user => new UserInfo
				{
					Id = user.Id,
					Name = user.Name,
					Surname = user.Surname,
					Username = user.Username,
					Email = user.Email,
					Roles = user.RoleForUsers.Select(ru => ru.UserRole.Code).ToList()
				}).FirstOrDefaultAsync(u => u.Id == idUser);

			if (user == null)
				return NotFound("Nie znaleziono danych użytkownika");
			return Ok(user);
		}
	}
}
