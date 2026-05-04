using VulnScanner.Domain.Enums;
using VulnScanner.Infrastructure.Data;
using VulnScanner.Services.Interfaces;

namespace VulnScanner.Jobs;

public class ScanJob
{
    private readonly AppDbContext _db;
    private readonly IZapService _zap;
    private readonly IScanResultService _results;
    private readonly ILogger<ScanJob> _logger;

    public ScanJob(AppDbContext db, IZapService zap, IScanResultService results, ILogger<ScanJob> logger)
    {
        _db = db;
        _zap = zap;
        _results = results;
        _logger = logger;
    }

    public async Task ExecuteAsync(int scanId)
    {
        var scan = await _db.Scans.FindAsync(scanId);
        if (scan == null)
        {
            _logger.LogWarning("Scan {ScanId} not found.", scanId);
            return;
        }

        scan.Status = ScanStatus.Running;
        scan.StartedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        try
        {
            var zapOutput = await _zap.RunScanAsync(scan.TargetUrl, scanId);
            await _results.SaveResultsAsync(scanId, zapOutput);
            scan.Status = ScanStatus.Completed;
            scan.CompletedAt = DateTime.UtcNow;
            _logger.LogInformation("Scan {ScanId} completed successfully.", scanId);
        }
        catch (Exception ex)
        {
            scan.Status = ScanStatus.Failed;
            scan.ErrorMessage = ex.Message;
            _logger.LogError(ex, "Scan {ScanId} failed.", scanId);
        }

        await _db.SaveChangesAsync();
    }
}
