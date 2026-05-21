# Crennotech Vulnerability Scanner

Internal vulnerability scanning platform built for **ISO 27001** compliance. This deliverable is the backend API platform (Phase 1). A React-based web frontend is planned as Phase 2 and is documented as future work in the design documentation.

## Tech Stack

| Layer            | Technology                       |
| ---------------- | -------------------------------- |
| Backend API      | ASP.NET Core 8 (.NET 8 SDK)     |
| Database         | Microsoft SQL Server (or LocalDB)|
| Background jobs  | Hangfire 1.8                     |
| ORM / migrations | EF Core 8                        |
| Scanner          | OWASP ZAP (REST API)             |
| Tests            | xUnit + Moq + EF InMemory        |
| API docs         | Swagger / OpenAPI                |
| Future frontend  | React (Phase 2 - not in scope)   |

## Solution Layout

```
VulnScanner.sln
├── VulnScanner.API              -> ASP.NET Core Web API host + Swagger
├── VulnScanner.Domain           -> Entities, enums, DTOs (no dependencies)
├── VulnScanner.Infrastructure   -> EF Core DbContext + migrations
├── VulnScanner.Services         -> ZAP integration, result parsing
├── VulnScanner.Jobs             -> Hangfire background job orchestration
└── VulnScanner.Tests            -> xUnit unit tests (InMemory + Moq)
```

## Quick Start (Development)

### Prerequisites

| Tool                        | Minimum     | Why                                             |
| --------------------------- | ----------- | ----------------------------------------------- |
| .NET SDK                    | 8.0         | Build / run the API                             |
| SQL Server LocalDB or higher | 2019        | Persistent storage for scans + Hangfire        |
| OWASP ZAP (daemon mode)     | 2.14        | Performs the actual scanning                    |
| Git                         | any recent  | Clone the repo                                  |

(Full minimum-requirements derivation is in `docs/system-maintenance.md`.)

### Steps

```bash
# 1. Clone
git clone https://github.com/andrew-ltu/crennotech-vuln-scanner.git
cd crennotech-vuln-scanner

# 2. Restore + build
dotnet restore
dotnet build

# 3. Update connection string in VulnScanner.API/appsettings.json
#    (default uses (localdb)\MSSQLLocalDB)

# 4. Create the database (first run only)
cd VulnScanner.API
dotnet ef migrations add InitialCreate --project ../VulnScanner.Infrastructure --startup-project .
dotnet ef database update --project ../VulnScanner.Infrastructure --startup-project .

# 5. Start OWASP ZAP in daemon mode (separate terminal)
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true

# 6. Run the API
dotnet run --project VulnScanner.API

# Swagger UI:        https://localhost:7180/swagger
# Hangfire dashboard: https://localhost:7180/hangfire
```

### Run the tests

```bash
dotnet test
```

## API Surface (summary)

| Verb   | Route                       | Purpose                              |
| ------ | --------------------------- | ------------------------------------ |
| POST   | `/api/scans`                | Trigger a new scan                   |
| GET    | `/api/scans`                | List all scans (newest first)        |
| GET    | `/api/scans/{id}`           | Get one scan                         |
| GET    | `/api/scans/{id}/status`    | Lightweight status poll              |
| GET    | `/api/scans/{id}/report`    | Aggregated findings + summary        |
| GET    | `/api/scans/{id}/raw`       | Raw ZAP JSON                         |
| DELETE | `/api/scans/{id}`           | Cancel a queued scan                 |

See `docs/user-manual.md` for full request/response examples and the Postman collection in `docs/postman/`.

## Documentation

| Document                       | Purpose                                                 |
| ------------------------------ | ------------------------------------------------------- |
| `docs/system-maintenance.md`   | Install, update, patch, deploy, dependencies, CVEs     |
| `docs/user-manual.md`          | End-user workflows via Swagger / Postman                |
| `docs/design.md`               | Architecture, threat model, UML, ER diagrams, rationale |

## License

See `LICENSE` for terms.
