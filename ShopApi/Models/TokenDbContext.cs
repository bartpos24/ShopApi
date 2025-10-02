using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using ShopApi.Models.Enums;

namespace ShopApi.Models
{
	public class TokenDbContext : DbContext
	{
		public TokenDbContext(DbContextOptions<TokenDbContext> options) : base(options) { }
		public virtual DbSet<ShopApiToken> ShopApiTokens { get; set; }

		protected override void OnModelCreating(ModelBuilder modelBuilder)
		{
			modelBuilder.Entity<ShopApiToken>(entity =>
			{
				entity.HasKey(e => e.Id);

				entity.ToTable("ShopApiToken");

				entity.Property(e => e.Id)
						.HasColumnName("Id");

				entity.Property(e => e.Guid)
						.HasColumnType("nvarchar")
						.HasMaxLength(36)
						.IsRequired()
						.HasConversion(new GuidToStringConverter())
						.HasColumnName("Guid");

				entity.Property(e => e.Username)
						.HasMaxLength(50)
						.IsUnicode()
						.IsRequired()
						.HasColumnName("Username");

				entity.Property(e => e.SSAID)
						.HasColumnType("nvarchar")
						.HasMaxLength(50)
						.IsRequired(false)
						.HasColumnName("SSAID");

				entity.Property(e => e.Roles)
				.HasColumnName("nvarchar")
				.HasMaxLength(200)
				.IsRequired()
				.HasColumnName("Roles");

				entity.Property(e => e.ExpirationDate)
						.IsRequired()
						.HasColumnType("datetime2")
						.HasColumnName("ExpirationDate");

				entity.Property(e => e.LoginType)
						.IsRequired()
						.HasConversion(new EnumToStringConverter<ELoginType>())
						.HasMaxLength(20)
						.HasColumnName("LicenseType");

				entity.OwnsOne<UserActivity>(e => e.LastActivity, o =>
				{
					o.ToTable("UserActivities");
				});

			});
		}
	}
}
