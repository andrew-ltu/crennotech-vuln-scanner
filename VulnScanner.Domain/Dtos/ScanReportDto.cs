namespace VulnScanner.Domain.Dtos;

/// <summary>
/// Aggregated report for a single scan, intended for API consumers
/// (e.g. Swagger UI, future React frontend, Postman, dashboards).
/// </summary>
public record ScanReportDto(
    int ScanId,
    string TargetUrl,
    string Status,
    DateTime CreatedAt,
    DateTime? StartedAt,
    DateTime? CompletedAt,
    ScanSummaryDto Summary,
    IReadOnlyList<ScanFindingDto> Findings);

public record ScanSummaryDto(
    int TotalFindings,
    int Critical,
    int High,
    int Medium,
    int Low,
    int Info);

public record ScanFindingDto(
    int Id,
    string AlertName,
    string Severity,
    string Url,
    string Description,
    string Solution,
    string Evidence,
    string CveId,
    DateTime DetectedAt);
