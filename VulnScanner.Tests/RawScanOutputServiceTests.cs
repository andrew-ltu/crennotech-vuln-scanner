using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using VulnScanner.Domain.Entities;
using VulnScanner.Infrastructure.Data;
using VulnScanner.Services;
using Xunit;

namespace VulnScanner.Tests;

public class RawScanOutputServiceTests
{
    private static AppDbContext NewDb(string name) =>
        new(new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(name).Options);

    [Fact]
    public async Task SaveRawOutputAsync_EmptyJson_DoesNothing()
    {
        using var db = NewDb(nameof(SaveRawOutputAsync_EmptyJson_DoesNothing));
        var svc = new RawScanOutputService(db, NullLogger<RawScanOutputService>.Instance);

        await svc.SaveRawOutputAsync(1, "");

        Assert.Empty(db.RawScanOutputs);
    }

    [Fact]
    public async Task SaveRawOutputAsync_PersistsRow()
    {
        using var db = NewDb(nameof(SaveRawOutputAsync_PersistsRow));
        var svc = new RawScanOutputService(db, NullLogger<RawScanOutputService>.Instance);

        await svc.SaveRawOutputAsync(7, """{ "alerts": [] }""");

        var row = Assert.Single(db.RawScanOutputs);
        Assert.Equal(7, row.ScanId);
        Assert.Equal("OWASP ZAP", row.ScannerName);
    }

    [Fact]
    public async Task GetRawOutputAsync_ReturnsMostRecentByScanId()
    {
        using var db = NewDb(nameof(GetRawOutputAsync_ReturnsMostRecentByScanId));
        db.RawScanOutputs.AddRange(
            new RawScanOutput { ScanId = 5, RawJson = "old",   CapturedAt = DateTime.UtcNow.AddHours(-2) },
            new RawScanOutput { ScanId = 5, RawJson = "new",   CapturedAt = DateTime.UtcNow },
            new RawScanOutput { ScanId = 6, RawJson = "other", CapturedAt = DateTime.UtcNow });
        await db.SaveChangesAsync();

        var svc = new RawScanOutputService(db, NullLogger<RawScanOutputService>.Instance);
        var raw = await svc.GetRawOutputAsync(5);

        Assert.Equal("new", raw);
    }

    [Fact]
    public async Task GetRawOutputAsync_NoMatch_ReturnsNull()
    {
        using var db = NewDb(nameof(GetRawOutputAsync_NoMatch_ReturnsNull));
        var svc = new RawScanOutputService(db, NullLogger<RawScanOutputService>.Instance);

        Assert.Null(await svc.GetRawOutputAsync(999));
    }
}
