namespace VulnScanner.Domain.Entities;

/// <summary>
/// A single vulnerability finding produced by a scan. One <see cref="Scan"/>
/// may have many <see cref="ScanResult"/> rows (one per ZAP alert).
/// </summary>
public class ScanResult
{
    public int Id { get; set; }

    public int ScanId { get; set; }
    public Scan Scan { get; set; } = null!;

    /// <summary>Human-readable name of the alert, e.g. "Cross-Site Scripting (Reflected)".</summary>
    public string AlertName { get; set; } = string.Empty;

    /// <summary>Critical, High, Medium, Low, Info. Stored as a string for query/filter friendliness.</summary>
    public string Severity { get; set; } = "Info";

    /// <summary>The URL the alert was raised against.</summary>
    public string Url { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;
    public string Solution { get; set; } = string.Empty;
    public string Evidence { get; set; } = string.Empty;
    public string Request { get; set; } = string.Empty;
    public string Response { get; set; } = string.Empty;

    /// <summary>CVE identifier(s) if reported by ZAP, otherwise empty.</summary>
    public string CveId { get; set; } = string.Empty;

    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}
