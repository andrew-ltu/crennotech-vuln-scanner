namespace VulnScanner.Domain.Entities;

public class RawScanOutput
{
    public int Id { get; set; }
    public int ScanId { get; set; }
    public Scan Scan { get; set; } = null!;
    public string RawJson { get; set; } = string.Empty;
    public string ScannerName { get; set; } = "OWASP ZAP";
    public DateTime CapturedAt { get; set; } = DateTime.UtcNow;
}
