using Hangfire;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnScanner.Domain.Entities;
using VulnScanner.Domain.Enums;
using VulnScanner.Infrastructure.Data;
using VulnScanner.Jobs;

namespace VulnScanner.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ScansController : ControllerBase
{
    private readonly AppDbContext _db;

    public ScansController(AppDbContext db)
    {
        _db = db;
    }

    [HttpPost]
    public async Task<IActionResult> TriggerScan([FromBody] ScanRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.TargetUrl))
            return BadRequest("TargetUrl is required.");

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

    [HttpGet]
    public async Task<IActionResult> GetAllScans()
    {
        var scans = await _db.Scans
            .OrderByDescending(s => s.CreatedAt)
            .Select(s => new { s.Id, Status = s.Status.ToString(), s.TargetUrl, s.CreatedAt, s.CompletedAt })
            .ToListAsync();
        return Ok(scans);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetScan(int id)
    {
        var scan = await _db.Scans.FindAsync(id);
        if (scan == null) return NotFound();
        return Ok(new { scan.Id, Status = scan.Status.ToString(), scan.TargetUrl, scan.CreatedAt, scan.StartedAt, scan.CompletedAt, scan.ErrorMessage });
    }

    [HttpGet("{id}/status")]
    public async Task<IActionResult> GetStatus(int id)
    {
        var scan = await _db.Scans.FindAsync(id);
        if (scan == null) return NotFound();
        return Ok(new { scan.Id, Status = scan.Status.ToString(), scan.StartedAt, scan.CompletedAt, scan.ErrorMessage });
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> CancelScan(int id)
    {
        var scan = await _db.Scans.FindAsync(id);
        if (scan == null) return NotFound();
        if (scan.Status != ScanStatus.Queued)
            return BadRequest("Only queued scans can be cancelled.");
        scan.Status = ScanStatus.Failed;
        scan.ErrorMessage = "Cancelled by user.";
        await _db.SaveChangesAsync();
        return Ok(new { message = $"Scan {id} cancelled." });
    }
}

public record ScanRequest(string TargetUrl);
