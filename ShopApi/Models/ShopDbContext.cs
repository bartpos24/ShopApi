using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ShopApi.Models.Database;

namespace ShopApi.Models
{
    public partial class ShopDbContext : DbContext
    {
        public ShopDbContext() { }
        public ShopDbContext(DbContextOptions<ShopDbContext> options) : base(options) { }

		public DbSet<InitProduct> InitProducts { get; set; }
		public DbSet<Product> Products { get; set; }
		public DbSet<Unit> Units { get; set; }
		public DbSet<Barcode> Barcodes { get; set; }

		public virtual DbSet<User> Users { get; set; }
		public DbSet<UserRole> UserRoles { get; set; }
		public DbSet<RoleForUser> RoleForUser { get; set; }  

		protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

			builder.Entity<RoleForUser>()
				.HasKey(r => new { r.UserId, r.UserRoleId });

			builder.Entity<RoleForUser>()
				.HasOne(r => r.User)
				.WithMany(u => u.RoleForUsers)
				.HasForeignKey(r => r.UserId);

			builder.Entity<RoleForUser>()
				.HasOne(r => r.UserRole)
				.WithMany(ur => ur.RoleForUsers)
				.HasForeignKey(r => r.UserRoleId);
		}
	}
}
