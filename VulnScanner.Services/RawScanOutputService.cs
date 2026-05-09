using VulnScanner.Domain.Entities;
using VulnScanner.Infrastructure.Data;
using VulnScanner.Services.Interfaces;

namespace VulnScanner.Services;

public class RawScanOutputService : IRawScanOutputService
{
    private readonly AppDbContext _db;
    private readonly ILogger<RawScanOutputService> _logger;

    public RawScanOutputService(AppDbContext db, ILogger<RawScanOutputService> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task SaveRawOutputAsync(int scanId, string rawJson, string scannerName = "OWASP ZAP")
    {
        if (string.IsNullOrWhiteSpace(rawJson))
        {
            _logger.LogWarning("Scan {ScanId} produced empty raw output.", scanId);
            return;
        }

        var output = new RawScanOutput
        {
            ScanId = scanId,
            RawJson = rawJson,
            ScannerName = scannerName,
            CapturedAt = DateTime.UtcNow
        };

        _db.RawScanOutputs.Add(output);
        await _db.SaveChangesAsync();
        _logger.LogInformation("Raw output saved for Scan {ScanId} from {Scanner}.", scanId, scannerName);
    }

    public async Task<string?> GetRawOutputAsync(int scanId)
    {
        var output = await _db.RawScanOutputs.FindAsync(scanId);
        return output?.RawJson;
    }
}
