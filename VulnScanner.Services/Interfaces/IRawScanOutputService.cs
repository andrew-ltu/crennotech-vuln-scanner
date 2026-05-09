namespace VulnScanner.Services.Interfaces;

public interface IRawScanOutputService
{
    Task SaveRawOutputAsync(int scanId, string rawJson, string scannerName = "OWASP ZAP");
    Task<string?> GetRawOutputAsync(int scanId);
}
