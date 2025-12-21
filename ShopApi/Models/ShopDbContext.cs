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
		public DbSet<ProductUnit> Units { get; set; }
		public DbSet<Barcode> Barcodes { get; set; }

		public virtual DbSet<User> Users { get; set; }
		public DbSet<UserRole> UserRoles { get; set; }
		public DbSet<RoleForUser> RoleForUser { get; set; }  
		public DbSet<InventoryStatus> InventoryStatus { get; set; }
		public DbSet<Inventory> Inventories { get; set; }
        public DbSet<InventoryPosition> InventoryPositions { get; set; }
        public DbSet<CommonInventoryPosition> CommonInventoryPositions { get; set; }

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

            builder.Entity<InventoryPosition>()
                .HasOne(ip => ip.User)
                .WithMany()
                .HasForeignKey(ip => ip.UserId)
                .OnDelete(DeleteBehavior.Restrict); // Change from Cascade to Restrict

            builder.Entity<InventoryPosition>()
                .HasOne(ip => ip.ModifiedByUser)
                .WithMany()
                .HasForeignKey(ip => ip.ModifiedByUserId)
                .OnDelete(DeleteBehavior.Restrict); // Keep as Restrict/NoAction

            builder.Entity<Inventory>()
                .HasOne(i => i.CreatedByUser)
                .WithMany()
                .HasForeignKey(i => i.CreatedByUserId)
                .OnDelete(DeleteBehavior.Restrict); // Change from Cascade to Restrict

            builder.Entity<CommonInventoryPosition>()
                .HasOne(ip => ip.User)
                .WithMany()
                .HasForeignKey(ip => ip.UserId)
                .OnDelete(DeleteBehavior.Restrict); // Change from Cascade to Restrict

            builder.Entity<CommonInventoryPosition>()
                .HasOne(ip => ip.ModifiedByUser)
                .WithMany()
                .HasForeignKey(ip => ip.ModifiedByUserId)
                .OnDelete(DeleteBehavior.Restrict);

            builder.Entity<CommonInventoryPosition>()
                .HasOne(ip => ip.Unit)
                .WithMany()
                .HasForeignKey(ip => ip.UnitId)
                .OnDelete(DeleteBehavior.Restrict);
        }
	}
}
