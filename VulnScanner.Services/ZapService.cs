using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using VulnScanner.Services.Interfaces;

namespace VulnScanner.Services;

/// <summary>
/// Drives an OWASP ZAP daemon over its REST API:
///   1. Spider the target to discover URLs.
///   2. Run an active scan against the discovered surface.
///   3. Pull the resulting alerts as JSON.
/// </summary>
public class ZapService : IZapService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _config;
    private readonly ILogger<ZapService> _logger;

    public ZapService(HttpClient httpClient, IConfiguration config, ILogger<ZapService> logger)
    {
        _httpClient = httpClient;
        _config = config;
        _logger = logger;
    }

    public async Task<string> RunScanAsync(string targetUrl, int scanId)
    {
        var zapBaseUrl = _config["Zap:BaseUrl"] ?? "http://localhost:8080";
        var apiKey = _config["Zap:ApiKey"] ?? string.Empty;

        _logger.LogInformation("Starting ZAP scan for Scan {ScanId} against {TargetUrl}", scanId, targetUrl);

        // --- Spider phase -------------------------------------------------
        var spiderUrl = $"{zapBaseUrl}/JSON/spider/action/scan/?apikey={apiKey}&url={Uri.EscapeDataString(targetUrl)}";
        var spiderResponse = await _httpClient.GetAsync(spiderUrl);
        spiderResponse.EnsureSuccessStatusCode();
        await WaitForSpiderAsync(zapBaseUrl, apiKey);

        // --- Active scan phase -------------------------------------------
        var scanUrl = $"{zapBaseUrl}/JSON/ascan/action/scan/?apikey={apiKey}&url={Uri.EscapeDataString(targetUrl)}";
        var scanResponse = await _httpClient.GetAsync(scanUrl);
        scanResponse.EnsureSuccessStatusCode();

        var scanContent = await scanResponse.Content.ReadAsStringAsync();
        using var scanData = JsonDocument.Parse(scanContent);
        var activeScanId = scanData.RootElement.GetProperty("scan").GetString()
            ?? throw new InvalidOperationException("ZAP did not return an active scan id.");

        await WaitForActiveScanAsync(zapBaseUrl, apiKey, activeScanId);

        // --- Report phase ------------------------------------------------
        var reportUrl = $"{zapBaseUrl}/JSON/core/view/alerts/?apikey={apiKey}&baseurl={Uri.EscapeDataString(targetUrl)}";
        var reportResponse = await _httpClient.GetAsync(reportUrl);
        reportResponse.EnsureSuccessStatusCode();

        var report = await reportResponse.Content.ReadAsStringAsync();
        _logger.LogInformation("ZAP scan completed for Scan {ScanId}", scanId);
        return report;
    }

    private async Task WaitForSpiderAsync(string zapBaseUrl, string apiKey)
    {
        int progress = 0;
        while (progress < 100)
        {
            await Task.Delay(2000);
            var response = await _httpClient.GetStringAsync($"{zapBaseUrl}/JSON/spider/view/status/?apikey={apiKey}");
            using var doc = JsonDocument.Parse(response);
            int.TryParse(doc.RootElement.GetProperty("status").GetString(), out progress);
        }
    }

    private async Task WaitForActiveScanAsync(string zapBaseUrl, string apiKey, string activeScanId)
    {
        int progress = 0;
        while (progress < 100)
        {
            await Task.Delay(3000);
            var response = await _httpClient.GetStringAsync($"{zapBaseUrl}/JSON/ascan/view/status/?apikey={apiKey}&scanId={activeScanId}");
            using var doc = JsonDocument.Parse(response);
            int.TryParse(doc.RootElement.GetProperty("status").GetString(), out progress);
        }
    }
}
