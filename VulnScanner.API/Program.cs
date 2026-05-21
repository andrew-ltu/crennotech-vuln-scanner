using Hangfire;
using Hangfire.SqlServer;
using Microsoft.EntityFrameworkCore;
using VulnScanner.Infrastructure.Data;
using VulnScanner.Jobs;
using VulnScanner.Services;
using VulnScanner.Services.Interfaces;

var builder = WebApplication.CreateBuilder(args);

// --- Configuration ---------------------------------------------------------
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' is not configured.");

// --- Database --------------------------------------------------------------
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(connectionString));

// --- Hangfire --------------------------------------------------------------
builder.Services.AddHangfire(config => config
    .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
    .UseSimpleAssemblyNameTypeSerializer()
    .UseRecommendedSerializerSettings()
    .UseSqlServerStorage(connectionString, new SqlServerStorageOptions
    {
        CommandBatchMaxTimeout = TimeSpan.FromMinutes(5),
        SlidingInvisibilityTimeout = TimeSpan.FromMinutes(5),
        QueuePollInterval = TimeSpan.Zero,
        UseRecommendedIsolationLevel = true,
        DisableGlobalLocks = true
    }));

builder.Services.AddHangfireServer();

// --- Application services --------------------------------------------------
// AddHttpClient<TInterface, TImplementation> already registers IZapService -> ZapService
// in DI; no separate AddScoped needed.
builder.Services.AddHttpClient<IZapService, ZapService>();
builder.Services.AddScoped<IScanResultService, ScanResultService>();
builder.Services.AddScoped<IRawScanOutputService, RawScanOutputService>();
builder.Services.AddScoped<ScanJob>();

// --- Web API ---------------------------------------------------------------
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new()
    {
        Title = "Crennotech Vulnerability Scanner API",
        Version = "v1",
        Description = "Internal vulnerability scanning platform for ISO 27001 compliance."
    });
});

// CORS for future frontend (React) - tighten origins in production.
builder.Services.AddCors(options =>
{
    options.AddPolicy("DefaultCors", policy =>
    {
        var origins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
                      ?? new[] { "http://localhost:5173", "http://localhost:3000" };
        policy.WithOrigins(origins).AllowAnyHeader().AllowAnyMethod();
    });
});

var app = builder.Build();

// --- Pipeline --------------------------------------------------------------
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseCors("DefaultCors");
app.UseAuthorization();

// Hangfire dashboard: protect in production with an IDashboardAuthorizationFilter.
app.UseHangfireDashboard("/hangfire");

app.MapControllers();

// Apply pending migrations on startup in non-production environments.
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.Migrate();
}

app.Run();

// Needed so WebApplicationFactory<Program> can find the entry point in integration tests.
public partial class Program { }
