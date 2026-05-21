using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;
using VulnScanner.Infrastructure.Data;
using VulnScanner.Jobs;
using VulnScanner.Services.Interfaces;
using Xunit;

namespace VulnScanner.Tests;

public class ScanJobTests
{
    private static AppDbContext NewDb(string name) =>
        new(new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(name).Options);

    [Fact]
    public async Task ExecuteAsync_MissingScan_ReturnsWithoutSideEffects()
    {
        using var db = NewDb(nameof(ExecuteAsync_MissingScan_ReturnsWithoutSideEffects));
        var zap = new Mock<IZapService>();
        var job = new ScanJob(db, zap.Object,
            new Mock<IScanResultService>().Object,
            new Mock<IRawScanOutputService>().Object,
            NullLogger<ScanJob>.Instance);

        await job.ExecuteAsync(999);

        zap.Verify(z => z.RunScanAsync(It.IsAny<string>(), It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task ExecuteAsync_HappyPath_TransitionsToCompleted()
    {
        using var db = NewDb(nameof(ExecuteAsync_HappyPath_TransitionsToCompleted));
        var scan = new Scan { TargetUrl = "https://target" };
        db.Scans.Add(scan);
        await db.SaveChangesAsync();

        var zap = new Mock<IZapService>();
        zap.Setup(z => z.RunScanAsync("https://target", scan.Id)).ReturnsAsync("""{"alerts":[]}""");

        var results = new Mock<IScanResultService>();
        var raw = new Mock<IRawScanOutputService>();

        var job = new ScanJob(db, zap.Object, results.Object, raw.Object, NullLogger<ScanJob>.Instance);
        await job.ExecuteAsync(scan.Id);

        var reloaded = db.Scans.Single();
        Assert.Equal(ScanStatus.Completed, reloaded.Status);
        Assert.NotNull(reloaded.StartedAt);
        Assert.NotNull(reloaded.CompletedAt);
        raw.Verify(r => r.SaveRawOutputAsync(scan.Id, """{"alerts":[]}""", "OWASP ZAP"), Times.Once);
        results.Verify(r => r.SaveResultsAsync(scan.Id, """{"alerts":[]}"""), Times.Once);
    }

    [Fact]
    public async Task ExecuteAsync_ZapThrows_MarksScanFailedWithErrorMessage()
    {
        using var db = NewDb(nameof(ExecuteAsync_ZapThrows_MarksScanFailedWithErrorMessage));
        var scan = new Scan { TargetUrl = "https://target" };
        db.Scans.Add(scan);
        await db.SaveChangesAsync();

        var zap = new Mock<IZapService>();
        zap.Setup(z => z.RunScanAsync(It.IsAny<string>(), It.IsAny<int>()))
           .ThrowsAsync(new HttpRequestException("ZAP unreachable"));

        var job = new ScanJob(db, zap.Object,
            new Mock<IScanResultService>().Object,
            new Mock<IRawScanOutputService>().Object,
            NullLogger<ScanJob>.Instance);

        await job.ExecuteAsync(scan.Id);

        var reloaded = db.Scans.Single();
        Assert.Equal(ScanStatus.Failed, reloaded.Status);
        Assert.Equal("ZAP unreachable", reloaded.ErrorMessage);
        Assert.NotNull(reloaded.CompletedAt);
    }

    [Fact]
    public async Task ExecuteAsync_AlreadyCompleted_DoesNotReRun()
    {
        using var db = NewDb(nameof(ExecuteAsync_AlreadyCompleted_DoesNotReRun));
        var scan = new Scan
        {
            TargetUrl = "https://target",
            Status = ScanStatus.Completed,
            CompletedAt = DateTime.UtcNow.AddMinutes(-5)
        };
        db.Scans.Add(scan);
        await db.SaveChangesAsync();

        var zap = new Mock<IZapService>();
        var job = new ScanJob(db, zap.Object,
            new Mock<IScanResultService>().Object,
            new Mock<IRawScanOutputService>().Object,
            NullLogger<ScanJob>.Instance);

        await job.ExecuteAsync(scan.Id);

        zap.Verify(z => z.RunScanAsync(It.IsAny<string>(), It.IsAny<int>()), Times.Never);
    }
}
