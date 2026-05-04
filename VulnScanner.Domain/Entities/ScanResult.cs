namespace VulnScanner.Domain.Entities;

public class ScanResult
{
    public int Id { get; set; }
    public int ScanId { get; set; }
    public Scan Scan { get; set; } = null!;
    public string AlertName { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string? Solution { get; set; }
    public string? Evidence { get; set; }
    public string? Request { get; set; }
    public string? Response { get; set; }
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}
