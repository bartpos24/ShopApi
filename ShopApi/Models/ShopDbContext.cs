﻿using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ShopApi.Models.Database;

namespace ShopApi.Models
{
    public partial class ShopDbContext : IdentityDbContext
    {
        public ShopDbContext() { }
        public ShopDbContext(DbContextOptions<ShopDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }

        public DbSet<InitProduct> InitProducts { get; set; }
        public DbSet<Product> Products { get; set; }
        public DbSet<Unit> Units { get; set; }
        public DbSet<Barcode> Barcodes { get; set; }
    }
}
