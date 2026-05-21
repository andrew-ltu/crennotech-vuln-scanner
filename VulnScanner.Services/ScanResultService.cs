using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
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

        await _db.ScanResults.AddRangeAsync(results);
        await _db.SaveChangesAsync();
        _logger.LogInformation("Saved {Count} results for Scan {ScanId}.", results.Count, scanId);
    }

    public async Task<IReadOnlyList<ScanResult>> GetResultsAsync(int scanId)
    {
        return await _db.ScanResults
            .AsNoTracking()
            .Where(r => r.ScanId == scanId)
            .OrderBy(r => r.Severity)
            .ToListAsync();
    }

    private static List<ScanResult> ParseZapAlerts(int scanId, string zapJson)
    {
        var results = new List<ScanResult>();
        using var doc = JsonDocument.Parse(zapJson);

        if (!doc.RootElement.TryGetProperty("alerts", out var alerts))
            return results;

        foreach (var alert in alerts.EnumerateArray())
        {
            var riskCode = alert.TryGetProperty("riskcode", out var rc) ? rc.GetString() : "0";
            results.Add(new ScanResult
            {
                ScanId = scanId,
                AlertName = GetString(alert, "alert"),
                Severity = MapRiskCodeToSeverity(riskCode),
                Url = GetString(alert, "url"),
                Description = GetString(alert, "description"),
                Solution = GetString(alert, "solution"),
                Evidence = GetString(alert, "evidence"),
                Request = GetString(alert, "request-header"),
                Response = GetString(alert, "response-header"),
                CveId = ExtractCve(alert),
                DetectedAt = DateTime.UtcNow
            });
        }
        return results;
    }

    private static string GetString(JsonElement element, string property)
        => element.TryGetProperty(property, out var val) ? val.GetString() ?? string.Empty : string.Empty;

    /// <summary>
    /// ZAP's "cweid" is a CWE, not a CVE. CVEs sometimes appear in the "reference"
    /// field. This is a best-effort extraction.
    /// </summary>
    private static string ExtractCve(JsonElement alert)
    {
        if (!alert.TryGetProperty("reference", out var refEl)) return string.Empty;
        var text = refEl.GetString() ?? string.Empty;
        var idx = text.IndexOf("CVE-", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return string.Empty;
        var end = idx + 4;
        while (end < text.Length && (char.IsDigit(text[end]) || text[end] == '-')) end++;
        return text.Substring(idx, end - idx);
    }

    private static string MapRiskCodeToSeverity(string? riskCode) => riskCode switch
    {
        "3" => "High",
        "2" => "Medium",
        "1" => "Low",
        "0" => "Info",
        _ => "Info"
    };
}
