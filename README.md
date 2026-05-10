# crennotech-vuln-scanner

Internal vulnerability scanning platform built for ISO 27001 compliance.

## Tech Stack

- **Backend** : .NET 8 Web API
- **Frontend** : React
- **Database** : SQL Server
- **Background Jobs** : Hangfire
- **Scanner** : OWASP ZAP

## Project Structure

- `VulnScanner.API` : REST API controllers and routing
- `VulnScanner.Domain` : Entities and enums
- `VulnScanner.Infrastructure` : EF Core DbContext and migrations
- `VulnScanner.Services` : Business logic and scanner integration
- `VulnScanner.Jobs` : Background scan job execution

## Features

- Trigger vulnerability scans against target URLs
- Background job processing via Hangfire
- Stores raw scanner output and structured scan results
- Track scan status (Queued → Running → Completed)
- REST endpoints for scan management

## Getting Started

1. Clone the repo
2. Update `appsettings.json` with your SQL Server connection string
3. Run EF migrations: `dotnet ef database update`
4. Start the API: `dotnet run`
5. Access Hangfire dashboard at `/hangfire`
