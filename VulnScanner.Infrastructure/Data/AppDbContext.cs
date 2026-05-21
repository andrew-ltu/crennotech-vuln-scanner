using Microsoft.EntityFrameworkCore;
using VulnScanner.Domain.Entities;

namespace VulnScanner.Infrastructure.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<Scan> Scans => Set<Scan>();
    public DbSet<ScanResult> ScanResults => Set<ScanResult>();
    public DbSet<RawScanOutput> RawScanOutputs => Set<RawScanOutput>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Scan>(entity =>
        {
            entity.HasKey(s => s.Id);
            entity.Property(s => s.TargetUrl).IsRequired().HasMaxLength(2048);
            entity.Property(s => s.Status).HasConversion<string>().HasMaxLength(20);
            entity.Property(s => s.ErrorMessage).HasMaxLength(4000);
            entity.HasIndex(s => s.CreatedAt);
            entity.HasIndex(s => s.Status);
        });

        modelBuilder.Entity<ScanResult>(entity =>
        {
            entity.HasKey(r => r.Id);
            entity.HasOne(r => r.Scan)
                  .WithMany()
                  .HasForeignKey(r => r.ScanId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.Property(r => r.Severity).HasMaxLength(20);
            entity.Property(r => r.AlertName).HasMaxLength(512);
            entity.Property(r => r.Url).HasMaxLength(2048);
            entity.Property(r => r.CveId).HasMaxLength(50);
            // Free-text columns: leave as nvarchar(max).
            entity.HasIndex(r => r.ScanId);
            entity.HasIndex(r => r.Severity);
        });

        modelBuilder.Entity<RawScanOutput>(entity =>
        {
            entity.HasKey(r => r.Id);
            entity.HasOne(r => r.Scan)
                  .WithMany()
                  .HasForeignKey(r => r.ScanId)
                  .OnDelete(DeleteBehavior.Cascade);
            entity.Property(r => r.ScannerName).HasMaxLength(100);
            entity.HasIndex(r => r.ScanId);
        });
    }
}
