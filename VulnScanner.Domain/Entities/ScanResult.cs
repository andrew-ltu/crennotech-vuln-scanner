namespace VulnScanner.Domain.Entities;

public class ScanResult
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ScanJobId { get; set; }
    public string TargetEndpoint { get; set; } = string.Empty;
    public ScanStatus Status { get; set; }
    public DateTime StartedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
    public List<ScanFinding> Findings { get; set; } = new();
    public ScanSummary Summary { get; set; } = new();
}

public class ScanFinding
{
    public string VulnerabilityId { get; set; } = string.Empty; // e.g. CVE-2024-1234
    public string Title { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public string Description { get; set; } = string.Empty;
    public string AffectedComponent { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
    public string RawOutput { get; set; } = string.Empty;
}

public class ScanSummary
{
    public int TotalFindings { get; set; }
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Informational { get; set; }
}

public enum Severity
{
    Informational,
    Low,
    Medium,
    High,
    Critical
}
