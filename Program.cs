using Hangfire;
using Hangfire.SqlServer;
using Microsoft.EntityFrameworkCore;
using VulnScanner.Infrastructure.Data;
using VulnScanner.Jobs;
using VulnScanner.Services;
using VulnScanner.Services.Interfaces;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddHangfire(config => config
    .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
    .UseSimpleAssemblyNameTypeSerializer()
    .UseRecommendedSerializerSettings()
    .UseSqlServerStorage(builder.Configuration.GetConnectionString("DefaultConnection"),
        new SqlServerStorageOptions
        {
            CommandBatchMaxTimeout = TimeSpan.FromMinutes(5),
            SlidingInvisibilityTimeout = TimeSpan.FromMinutes(5),
            QueuePollInterval = TimeSpan.Zero,
            UseRecommendedIsolationLevel = true,
            DisableGlobalLocks = true
        }));

builder.Services.AddHangfireServer();
builder.Services.AddHttpClient<IZapService, ZapService>();
builder.Services.AddScoped<ScanJob>();
builder.Services.AddScoped<IZapService, ZapService>();
builder.Services.AddScoped<IScanResultService, ScanResultService>();
builder.Services.AddScoped<IScanResultFormatterService, ScanResultFormatterService>();
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHangfireDashboard("/hangfire");
app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();
