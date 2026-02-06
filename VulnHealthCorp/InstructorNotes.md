# HealthCorp CTF - Instructor Notes

## Overview
HealthCorp is a deliberately vulnerable healthcare management system designed to simulate a real-world enterprise .NET environment. It contains a mix of modern ASP.NET Core logic and legacy patterns.

## Vulnerability Map

### 1. SQL Injection
*   **Easy Version**: `HealthCorp.Web.Controllers.AccountController.Login`.
    *   **Mechanism**: String concatenation in a raw SQL query.
    *   **Detection**: SAST will flag `FromSqlRaw`.
*   **Hard Version** (Conceptual): Dynamic filtering in `Legacy` project (not fully wired in this simplified deployment, but `SerializationHelper` exists).

### 2. Authentication Bypass
*   **Easy Version**: `HealthCorp.Web.Middleware.LegacyAuthMiddleware`.
    *   **Mechanism**: Checks for `X-HealthCorp-Admin` header or `HC_User` cookie without validation.
    *   **Detection**: Reviewing `Program.cs` middleware pipeline.

### 3. Broken Access Control (IDOR)
*   **Easy Version**: `HealthCorp.Web.Controllers.PatientsController` (Details, Edit, Delete).
    *   **Mechanism**: No check if the current user matches the requested Patient ID.
    *   **Detection**: Manual testing by changing IDs in URL.

### 4. File Upload & RCE
*   **Easy Version**: `HealthCorp.Web.Controllers.MedicalRecordsController.Upload`.
    *   **Mechanism**: Checks extension only, allowing path traversal in `FileName`.
    *   **Detection**: Reviewing file handling logic.

### 5. SSRF
*   **Easy Version**: `HealthCorp.Web.Controllers.MedicalRecordsController.PreviewImage`.
    *   **Mechanism**: Takes a `url` parameter and fetches it using `HttpClient` without validation.
    *   **Detection**: Searching for `HttpClient.Get...` with user input.

### 6. Logging / Sensitive Data Exposure
*   **Mechanism**: `HealthCorp.Infrastructure.Services.AuditService` logs sensitive objects as JSON to the console/file logger.
*   **Detection**: Code review of `AuditService`.

### 7. Business Logic / Race Condition
*   **Mechanism**: `HealthCorp.Web.Controllers.AppointmentsController.Create`.
    *   **Mechanism**: Checks for double booking then writes, but operation is not atomic/locked.
    *   **Detection**: identifying lack of transactions or constraints.

### 8. Insecure Deserialization
*   **Mechanism**: `HealthCorp.Legacy.SerializationHelper`.
    *   **Mechanism**: Uses `BinaryFormatter`.
    *   **Detection**: Grepping for `BinaryFormatter`.

## Architecture Notes
- The project assumes an Oracle Database. If running locally without Oracle, `UseOracle` might fail at runtime, but the code structure is valid for review.
- EF Core versions were downgraded to 8.x to maintain compatibility with the Oracle provider.

## CTF Goals
Students should be able to:
1.  Identify the SQLi in Login.
2.  Bypass Auth using the Legacy header.
3.  Access other users' patient data via IDOR.
4.  Upload a file with path traversal/malicious content.
5.  Trigger SSRF or Insecure Deserialization via code analysis.
