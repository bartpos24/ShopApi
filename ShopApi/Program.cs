using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using ShopApi.Interfaces.Repositories;
using ShopApi.Interfaces.Services;
using ShopApi.Models;
using ShopApi.Models.Database;
using ShopApi.OpenFoodFactsAPI;
using ShopApi.OpenFoodFactsAPI.Service;
using ShopApi.Repositories;
using ShopApi.Security;
using ShopApi.Security.Licensing;
using ShopApi.Services;
using ShopApi.Services.Background;
using ShopApi.Utilities;
using System.Security.Claims;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

//Database Connection
builder.Services.AddDbContext<ShopDbContext>(options => options.UseSqlServer(builder.Configuration.GetConnectionString("ShopDatabase")).EnableSensitiveDataLogging(true));
//builder.Services.AddDefaultIdentity<IdentityUser>().AddRoles<IdentityRole>().AddEntityFrameworkStores<ShopDbContext>();
builder.Services.AddDbContext<TokenDbContext>(options => options.UseInMemoryDatabase("ShopApiTokenDb"));

builder.Services.Configure<TokenSettings>(builder.Configuration.GetSection("Jwt"));
builder.Services.Configure<TokenExpirationBackgroundServiceSettings>(builder.Configuration.GetSection("BackgroundServices:TokenExpirationBackgroundService"));
builder.Services.AddScoped<TokenEvents>();
builder.Services.AddSingleton<IAuditActivityChannel, AuditActivityChannel>();
builder.Services.AddHostedService<TokenExpirationBackgroundService>();
builder.Services.AddHostedService<AuditActivityBackgroundService>();
builder.Services.AddScoped<ILicenseManager, LicenseManager>();
#region
//Configuration Services
builder.Services.AddScoped<IProductRepository, ProductRepository>();
builder.Services.AddHttpClient<IOpenFoodFactsApiClient, OpenFoodFactsApiClient>();
builder.Services.AddScoped<IOpenFoodFactsService, OpenFoodFactsService>();
builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();
builder.Services.AddScoped<IAuthService, AuthService>();
#endregion

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireLowercase = true;
    options.SignIn.RequireConfirmedEmail = false;
    options.User.RequireUniqueEmail = true;
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
		var tokenSettings = builder.Configuration.GetConfig<TokenSettings>("Jwt");
		options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = tokenSettings.Issuer,
            ValidAudience = tokenSettings.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(tokenSettings.JWTAccessSecretKey)),
			ClockSkew = TimeSpan.FromSeconds(tokenSettings.ClockSkewSeconds),
			RoleClaimType = ClaimTypes.Role
        };
		options.EventsType = typeof(TokenEvents);
		// Obs³uga zdarzeñ JWT
		//options.Events = new JwtBearerEvents
		//{
		//	OnAuthenticationFailed = context =>
		//	{
		//		Console.WriteLine("Authentication failed: " + context.Exception.Message);
		//		return Task.CompletedTask;
		//	},
		//	OnTokenValidated = context =>
		//	{
		//		Console.WriteLine("Token validated successfully");
		//		return Task.CompletedTask;
		//	}
		//};
	});

builder.Services.AddControllers().AddJsonOptions(options =>
{
	options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
	options.JsonSerializerOptions.WriteIndented = false;
	options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
	options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
});
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(config =>
{
	config.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
	{
		Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
		Name = "Authorization",
		In = ParameterLocation.Header,
		Type = SecuritySchemeType.ApiKey,
		Scheme = "Bearer"
	});

	config.AddSecurityRequirement(new OpenApiSecurityRequirement
	{
		{
			new OpenApiSecurityScheme
			{
				Reference = new OpenApiReference
				{
					Type = ReferenceType.SecurityScheme,
					Id = "Bearer"
				}
			},
			new string[] {}
		}
	});
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();


