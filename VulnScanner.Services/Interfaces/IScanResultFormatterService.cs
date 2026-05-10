namespace VulnScanner.Services.Interfaces;

public interface IScanResultFormatterService
{
    ScanResult FormatFromRawOutput(RawScanOutput raw);
}
