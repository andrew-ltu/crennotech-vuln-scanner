using Hangfire;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnScanner.Domain.Dtos;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;
using VulnScanner.Infrastructure.Data;
using VulnScanner.Jobs;
using VulnScanner.Services.Interfaces;

namespace VulnScanner.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class ScansController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IScanResultService _results;
    private readonly IRawScanOutputService _rawOutput;

    public ScansController(
        AppDbContext db,
        IScanResultService results,
        IRawScanOutputService rawOutput)
    {
        _db = db;
        _results = results;
        _rawOutput = rawOutput;
    }

    /// <summary>Trigger a new vulnerability scan against the given target URL.</summary>
    [HttpPost]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> TriggerScan([FromBody] ScanRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.TargetUrl))
            return BadRequest("TargetUrl is required.");

        if (!Uri.TryCreate(request.TargetUrl, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return BadRequest("TargetUrl must be a valid absolute http(s) URL.");
        }

        var scan = new Scan { TargetUrl = request.TargetUrl };
        _db.Scans.Add(scan);
        await _db.SaveChangesAsync();

        BackgroundJob.Enqueue<ScanJob>(job => job.ExecuteAsync(scan.Id));

        return CreatedAtAction(nameof(GetScan), new { id = scan.Id }, new
        {
            scan.Id,
            Status = scan.Status.ToString(),
            scan.TargetUrl,
            scan.CreatedAt
        });
    }

    /// <summary>List all scans, newest first.</summary>
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> GetAllScans()
    {
        var scans = await _db.Scans
            .AsNoTracking()
            .OrderByDescending(s => s.CreatedAt)
            .Select(s => new { s.Id, Status = s.Status.ToString(), s.TargetUrl, s.CreatedAt, s.CompletedAt })
            .ToListAsync();
        return Ok(scans);
    }

    /// <summary>Get a single scan by id.</summary>
    [HttpGet("{id:int}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetScan(int id)
    {
        var scan = await _db.Scans.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id);
        if (scan == null) return NotFound();
        return Ok(new
        {
            scan.Id,
            Status = scan.Status.ToString(),
            scan.TargetUrl,
            scan.CreatedAt,
            scan.StartedAt,
            scan.CompletedAt,
            scan.ErrorMessage
        });
    }

    /// <summary>Get just the status of a scan (lightweight polling endpoint).</summary>
    [HttpGet("{id:int}/status")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetStatus(int id)
    {
        var scan = await _db.Scans.AsNoTracking()
            .Where(s => s.Id == id)
            .Select(s => new { s.Id, s.Status, s.StartedAt, s.CompletedAt, s.ErrorMessage })
            .FirstOrDefaultAsync();
        if (scan == null) return NotFound();
        return Ok(new { scan.Id, Status = scan.Status.ToString(), scan.StartedAt, scan.CompletedAt, scan.ErrorMessage });
    }

    /// <summary>Get the full aggregated report (summary + findings) for a scan.</summary>
    [HttpGet("{id:int}/report")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetReport(int id)
    {
        var scan = await _db.Scans.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id);
        if (scan == null) return NotFound();

        var findings = await _results.GetResultsAsync(id);

        var summary = new ScanSummaryDto(
            TotalFindings: findings.Count,
            Critical: findings.Count(f => f.Severity == "Critical"),
            High: findings.Count(f => f.Severity == "High"),
            Medium: findings.Count(f => f.Severity == "Medium"),
            Low: findings.Count(f => f.Severity == "Low"),
            Info: findings.Count(f => f.Severity == "Info"));

        var report = new ScanReportDto(
            ScanId: scan.Id,
            TargetUrl: scan.TargetUrl,
            Status: scan.Status.ToString(),
            CreatedAt: scan.CreatedAt,
            StartedAt: scan.StartedAt,
            CompletedAt: scan.CompletedAt,
            Summary: summary,
            Findings: findings.Select(f => new ScanFindingDto(
                f.Id, f.AlertName, f.Severity, f.Url, f.Description,
                f.Solution, f.Evidence, f.CveId, f.DetectedAt)).ToList());

        return Ok(report);
    }

    /// <summary>Get the raw scanner output (the ZAP JSON) for a scan.</summary>
    [HttpGet("{id:int}/raw")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetRawOutput(int id)
    {
        var raw = await _rawOutput.GetRawOutputAsync(id);
        if (raw == null) return NotFound();
        return Content(raw, "application/json");
    }

    /// <summary>Cancel a queued scan. Running scans cannot be cancelled.</summary>
    [HttpDelete("{id:int}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> CancelScan(int id)
    {
        var scan = await _db.Scans.FindAsync(id);
        if (scan == null) return NotFound();
        if (scan.Status != ScanStatus.Queued)
            return BadRequest("Only queued scans can be cancelled.");
        scan.Status = ScanStatus.Failed;
        scan.ErrorMessage = "Cancelled by user.";
        scan.CompletedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();
        return Ok(new { message = $"Scan {id} cancelled." });
    }
}

public record ScanRequest(string TargetUrl);
