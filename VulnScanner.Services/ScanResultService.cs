using System.Text.Json;
using VulnScanner.Domain.Entities;
using VulnScanner.Infrastructure.Data;
using VulnScanner.Services.Interfaces;

namespace VulnScanner.Services;

public class ScanResultService : IScanResultService
{
    private readonly AppDbContext _db;
    private readonly ILogger<ScanResultService> _logger;

    public ScanResultService(AppDbContext db, ILogger<ScanResultService> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task SaveResultsAsync(int scanId, string zapJson)
    {
        if (string.IsNullOrWhiteSpace(zapJson))
        {
            _logger.LogWarning("Scan {ScanId} returned empty ZAP output.", scanId);
            return;
        }

        List<ScanResult> results;
        try
        {
            results = ParseZapAlerts(scanId, zapJson);
        }
        catch (JsonException ex)
        {
            _logger.LogError(ex, "Failed to parse ZAP JSON for Scan {ScanId}.", scanId);
            throw new InvalidOperationException($"ZAP output could not be parsed for scan {scanId}.", ex);
        }

        if (results.Count == 0)
        {
            _logger.LogInformation("Scan {ScanId} completed with no alerts.", scanId);
            return;
        }

        try
        {
            await _db.ScanResults.AddRangeAsync(results);
            await _db.SaveChangesAsync();
            _logger.LogInformation("Saved {Count} results for Scan {ScanId}.", results.Count, scanId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Database error saving results for Scan {ScanId}.", scanId);
            throw;
        }
    }

    public async Task<IEnumerable<ScanResult>> GetResultsAsync(int scanId)
    {
        return await Task.FromResult(
            _db.ScanResults.Where(r => r.ScanId == scanId).OrderBy(r => r.Severity).AsEnumerable()
        );
    }

    private static List<ScanResult> ParseZapAlerts(int scanId, string zapJson)
    {
        var results = new List<ScanResult>();
        var doc = JsonDocument.Parse(zapJson);
        if (!doc.RootElement.TryGetProperty("alerts", out var alerts)) return results;

        foreach (var alert in alerts.EnumerateArray())
        {
            var riskCode = alert.TryGetProperty("riskcode", out var rc) ? rc.GetString() : "0";
            results.Add(new ScanResult
            {
                ScanId = scanId,
                AlertName = GetString(alert, "alert"),
                Severity = MapRiskCodeToSeverity(riskCode),
                Url = GetString(alert, "url"),
                Description = GetString(alert, "desc"),
                Solution = GetString(alert, "solution"),
                Evidence = GetString(alert, "evidence"),
                Request = GetString(alert, "request-header"),
                Response = GetString(alert, "response-header"),
                DetectedAt = DateTime.UtcNow
            });
        }
        return results;
    }

    private static string GetString(JsonElement element, string property)
        => element.TryGetProperty(property, out var val) ? val.GetString() ?? "" : "";

    private static string MapRiskCodeToSeverity(string? riskCode) => riskCode switch
    {
        "3" => "Critical",
        "2" => "High",
        "1" => "Medium",
        "0" => "Low",
        _ => "Info"
    };
}
