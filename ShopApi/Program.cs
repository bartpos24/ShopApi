using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using ShopApi.Interfaces.Repositories;
using ShopApi.Models;
using ShopApi.OpenFoodFactsAPI;
using ShopApi.OpenFoodFactsAPI.Service;
using ShopApi.Repositories;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

//Database Connection
builder.Services.AddDbContext<ShopDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("ShopDatabase")).EnableSensitiveDataLogging(true));
//builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true).AddEntityFrameworkStores<ShopDbContext>();
#region
//Configuration Services
builder.Services.AddScoped<IProductRepository, ProductRepository>();
builder.Services.AddHttpClient<IOpenFoodFactsApiClient, OpenFoodFactsApiClient>();
builder.Services.AddScoped<IOpenFoodFactsService, OpenFoodFactsService>();
#endregion



builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();


