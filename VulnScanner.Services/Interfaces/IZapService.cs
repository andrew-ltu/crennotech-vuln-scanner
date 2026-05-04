namespace VulnScanner.Services.Interfaces;

public interface IZapService
{
    Task<string> RunScanAsync(string targetUrl, int scanId);
}
