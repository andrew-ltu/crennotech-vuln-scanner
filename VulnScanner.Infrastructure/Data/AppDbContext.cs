using Microsoft.EntityFrameworkCore;
using VulnScanner.Domain.Entities;

namespace VulnScanner.Infrastructure.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<Scan> Scans => Set<Scan>();
    public DbSet<ScanResult> ScanResults => Set<ScanResult>();
    public DbSet<Target> Targets => Set<Target>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Scan>(entity =>
        {
            entity.HasKey(s => s.Id);
            entity.Property(s => s.TargetUrl).IsRequired().HasMaxLength(2048);
            entity.Property(s => s.Status).HasConversion<string>();
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
        });

        modelBuilder.Entity<Target>(entity =>
        {
            entity.HasKey(t => t.Id);
            entity.Property(t => t.Name).IsRequired().HasMaxLength(200);
            entity.Property(t => t.Address).IsRequired().HasMaxLength(2048);
            entity.Property(t => t.Description).HasMaxLength(500);
        });
    }
}
