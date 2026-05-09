using VulnScanner.Domain.Enums;
using VulnScanner.Infrastructure.Data;
using VulnScanner.Services.Interfaces;

namespace VulnScanner.Jobs;

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

        // Queued → Running
        scan.Status = ScanStatus.Running;
        scan.StartedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        try
        {
            // Run ZAP and capture raw output
            var zapJson = await _zap.RunScanAsync(scan.TargetUrl, scanId);

            // Save raw output before parsing (CREN-89)
            await _rawOutput.SaveRawOutputAsync(scanId, zapJson);

            // Parse and store structured results (CREN-90)
            await _results.SaveResultsAsync(scanId, zapJson);

            // Running → Completed
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
