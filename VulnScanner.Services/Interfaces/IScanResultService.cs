using VulnScanner.Domain.Entities;

namespace VulnScanner.Services.Interfaces;

public interface IScanResultService
{
    Task SaveResultsAsync(int scanId, string zapJson);
    Task<IEnumerable<ScanResult>> GetResultsAsync(int scanId);
}
