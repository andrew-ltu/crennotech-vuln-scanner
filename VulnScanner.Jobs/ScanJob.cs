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
 
    // POST /api/scans
    // CREN-88: Accepts either a free-text TargetUrl or a predefined TargetId
    [HttpPost]
    public async Task<IActionResult> TriggerScan([FromBody] ScanRequest request)
    {
        string resolvedUrl;
 
        if (request.TargetId.HasValue)
        {
            var target = await _db.Targets.FindAsync(request.TargetId.Value);
            if (target == null)
                return NotFound(new { message = $"Target with ID {request.TargetId} not found." });
 
            resolvedUrl = target.Address;
        }
        else if (!string.IsNullOrWhiteSpace(request.TargetUrl))
        {
            resolvedUrl = request.TargetUrl.Trim();
        }
        else
        {
            return BadRequest("Provide either a TargetUrl or a TargetId.");
        }
 
        var scan = new Scan { TargetUrl = resolvedUrl };
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
 
    // GET /api/scans/targets
    // CREN-88: Returns predefined targets for the frontend dropdown
    [HttpGet("targets")]
    public async Task<IActionResult> GetTargets()
    {
        var targets = await _db.Targets
            .OrderBy(t => t.Name)
            .Select(t => new { t.Id, t.Name, t.Address, t.Description })
            .ToListAsync();
 
        return Ok(targets);
    }
 
    // GET /api/scans
    [HttpGet]
    public async Task<IActionResult> GetAllScans()
    {
        var scans = await _db.Scans
            .OrderByDescending(s => s.CreatedAt)
            .Select(s => new { s.Id, Status = s.Status.ToString(), s.TargetUrl, s.CreatedAt, s.CompletedAt })
            .ToListAsync();
 
        return Ok(scans);
    }
 
    // GET /api/scans/{id}
    [HttpGet("{id}")]
    public async Task<IActionResult> GetScan(int id)
    {
        var scan = await _db.Scans.FindAsync(id);
        if (scan == null) return NotFound();
 
        return Ok(new { scan.Id, Status = scan.Status.ToString(), scan.TargetUrl, scan.CreatedAt, scan.StartedAt, scan.CompletedAt, scan.ErrorMessage });
    }
 
    // GET /api/scans/{id}/status
    [HttpGet("{id}/status")]
    public async Task<IActionResult> GetStatus(int id)
    {
        var scan = await _db.Scans.FindAsync(id);
        if (scan == null) return NotFound();
 
        return Ok(new { scan.Id, Status = scan.Status.ToString(), scan.StartedAt, scan.CompletedAt, scan.ErrorMessage });
    }
 
    // DELETE /api/scans/{id}
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
 
public record ScanRequest(string? TargetUrl, int? TargetId);
