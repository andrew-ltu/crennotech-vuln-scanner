using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using VulnScanner.Infrastructure.Data;
using VulnScanner.Services;
using Xunit;

namespace VulnScanner.Tests;

public class ScanResultServiceTests
{
    private static AppDbContext NewDb(string name)
    {
        var opts = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(name)
            .Options;
        return new AppDbContext(opts);
    }

    [Fact]
    public async Task SaveResultsAsync_EmptyJson_DoesNothing()
    {
        using var db = NewDb(nameof(SaveResultsAsync_EmptyJson_DoesNothing));
        var svc = new ScanResultService(db, NullLogger<ScanResultService>.Instance);

        await svc.SaveResultsAsync(1, "");

        Assert.Empty(db.ScanResults);
    }

    [Fact]
    public async Task SaveResultsAsync_NoAlertsArray_DoesNothing()
    {
        using var db = NewDb(nameof(SaveResultsAsync_NoAlertsArray_DoesNothing));
        var svc = new ScanResultService(db, NullLogger<ScanResultService>.Instance);

        await svc.SaveResultsAsync(1, """{ "unrelated": "value" }""");

        Assert.Empty(db.ScanResults);
    }

    [Fact]
    public async Task SaveResultsAsync_MalformedJson_ThrowsInvalidOperation()
    {
        using var db = NewDb(nameof(SaveResultsAsync_MalformedJson_ThrowsInvalidOperation));
        var svc = new ScanResultService(db, NullLogger<ScanResultService>.Instance);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => svc.SaveResultsAsync(1, "{ not valid json"));
    }

    [Fact]
    public async Task SaveResultsAsync_HappyPath_PersistsAllAlertsWithCorrectSeverity()
    {
        const string zapJson = """
        {
          "alerts": [
            { "alert": "SQLi", "riskcode": "3", "url": "https://target/login", "description": "d1", "solution": "s1", "evidence": "ev1" },
            { "alert": "XSS",  "riskcode": "2", "url": "https://target/search", "description": "d2", "solution": "s2", "evidence": "ev2" },
            { "alert": "Info", "riskcode": "0", "url": "https://target/", "description": "d3", "solution": "s3", "evidence": "ev3" }
          ]
        }
        """;

        using var db = NewDb(nameof(SaveResultsAsync_HappyPath_PersistsAllAlertsWithCorrectSeverity));
        var svc = new ScanResultService(db, NullLogger<ScanResultService>.Instance);

        await svc.SaveResultsAsync(42, zapJson);

        var rows = db.ScanResults.OrderBy(r => r.AlertName).ToList();
        Assert.Equal(3, rows.Count);
        Assert.All(rows, r => Assert.Equal(42, r.ScanId));
        Assert.Equal("Info", rows.First(r => r.AlertName == "Info").Severity);
        Assert.Equal("Medium", rows.First(r => r.AlertName == "XSS").Severity);
        Assert.Equal("High", rows.First(r => r.AlertName == "SQLi").Severity);
    }

    [Fact]
    public async Task GetResultsAsync_ReturnsOnlyMatchingScanId()
    {
        using var db = NewDb(nameof(GetResultsAsync_ReturnsOnlyMatchingScanId));
        db.ScanResults.AddRange(
            new() { ScanId = 1, AlertName = "A", Severity = "High" },
            new() { ScanId = 1, AlertName = "B", Severity = "Low" },
            new() { ScanId = 2, AlertName = "C", Severity = "High" });
        await db.SaveChangesAsync();

        var svc = new ScanResultService(db, NullLogger<ScanResultService>.Instance);
        var results = await svc.GetResultsAsync(1);

        Assert.Equal(2, results.Count);
        Assert.All(results, r => Assert.Equal(1, r.ScanId));
    }
}
