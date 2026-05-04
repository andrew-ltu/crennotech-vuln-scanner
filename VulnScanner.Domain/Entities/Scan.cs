using VulnScanner.Domain.Enums;

namespace VulnScanner.Domain.Entities;

public class Scan
{
    public int Id { get; set; }
    public string TargetUrl { get; set; } = string.Empty;
    public ScanStatus Status { get; set; } = ScanStatus.Queued;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? StartedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
    public string? ErrorMessage { get; set; }
}
