using Microsoft.Extensions.Logging;
using VulnScanner.Domain.Enums;
using VulnScanner.Infrastructure.Data;
using VulnScanner.Services.Interfaces;

namespace VulnScanner.Jobs;

/// <summary>
/// Hangfire background job: orchestrates a single scan end-to-end.
/// Queued -> Running -> (Completed | Failed).
/// </summary>
public class ScanJob
{
    private readonly AppDbContext _db;
    private readonly IZapService _zap;
    private readonly IScanResultService _results;
    private readonly IRawScanOutputService _rawOutput;
    private readonly ILogger<ScanJob> _logger;

    public ScanJob(
        AppDbContext db,
        IZapService zap,
        IScanResultService results,
        IRawScanOutputService rawOutput,
        ILogger<ScanJob> logger)
    {
        _db = db;
        _zap = zap;
        _results = results;
        _rawOutput = rawOutput;
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

        // Don't re-run cancelled / completed scans.
        if (scan.Status is ScanStatus.Completed or ScanStatus.Failed)
        {
            _logger.LogInformation("Scan {ScanId} already in terminal state {Status}; skipping.", scanId, scan.Status);
            return;
        }

        scan.Status = ScanStatus.Running;
        scan.StartedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        try
        {
            var zapJson = await _zap.RunScanAsync(scan.TargetUrl, scanId);

            // Save raw output first so we always have evidence even if parsing fails.
            await _rawOutput.SaveRawOutputAsync(scanId, zapJson);
            await _results.SaveResultsAsync(scanId, zapJson);

            scan.Status = ScanStatus.Completed;
            scan.CompletedAt = DateTime.UtcNow;
            _logger.LogInformation("Scan {ScanId} completed successfully.", scanId);
        }
        catch (Exception ex)
        {
            scan.Status = ScanStatus.Failed;
            scan.CompletedAt = DateTime.UtcNow;
            scan.ErrorMessage = ex.Message;
            _logger.LogError(ex, "Scan {ScanId} failed.", scanId);
        }

        await _db.SaveChangesAsync();
    }
}
