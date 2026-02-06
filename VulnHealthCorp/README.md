# HealthCorp Application Setup Guide

This document outlines the steps to set up, configure, and execute the HealthCorp vulnerable .NET application.

## 1. Prerequisites

Ensure you have the following installed on your system:
*   **.NET 9.0 SDK**: [Download .NET 9.0](https://dotnet.microsoft.com/download/dotnet/9.0)
*   **Oracle Database**: A running instance of Oracle Database (e.g., Oracle Database Express Edition (XE) or a Docker container).
*   **Git**: Version control tool.

## 2. Project Setup

1.  **Clone/Open the Repository**:
    Navigate to the project root directory containing the `HealthCorp.sln` file.

    ```bash
    cd path/to/dotnetvulnerableapp
    ```

2.  **Restore Dependencies**:
    Run the following command to restore all NuGet packages required by the solution.

    ```bash
    dotnet restore
    ```

## 3. Project Structure & Architecture

The solution is divided into four distinct projects, simulating a layered enterprise architecture:

### 1. `HealthCorp.Web` (ASP.NET Core MVC/API)
*   **Role**: The presentation layer and entry point of the application.
*   **Contents**: Controllers, Views (Razor), wwwroot (static files), and startup configuration (`Program.cs`, `appsettings.json`).
*   **Vulnerabilities**: Contains the majority of web-facing vulnerabilities (SQL Injection in `AccountController`, IDOR in `PatientsController`, XSS in Views, etc.).

### 2. `HealthCorp.Core` (Class Library)
*   **Role**: The domain layer containing business entities and interfaces.
*   **Contents**:
    *   **Entities**: `User`, `Patient`, `Appointment`, `MedicalRecord`, `AuditLog`.
    *   **Interfaces**: `IAuditService` and other core abstractions.
*   **Notes**: Defined with clean architecture principles in mind but populated with realistic (and sometimes simplified) business objects.

### 3. `HealthCorp.Infrastructure` (Class Library)
*   **Role**: The data access and implementation layer.
*   **Contents**:
    *   **Data**: `ApplicationDbContext` (EF Core context configuration).
    *   **Services**: `AuditService` implementation.
*   **Vulnerabilities**: Contains the flawed `AuditService` that logs sensitive object data directly to text, violating security best practices.

### 4. `HealthCorp.Legacy` (Class Library)
*   **Role**: A library representing older, pre-existing code that the modern app integrates with.
*   **Contents**: `SerializationHelper`.
*   **Vulnerabilities**: Contains the **Insecure Deserialization** vulnerability via the deprecated `BinaryFormatter`, simulating a common issue when maintaining legacy integrations.

## 4. Database Setup

The application uses Entity Framework Core with an Oracle Database provider.

### Configure Connection String

1.  Open `src/HealthCorp.Web/appsettings.json`.
2.  Locate the `ConnectionStrings` section.
3.  Update the `DefaultConnection` string to match your Oracle Database instance credentials and host.

    ```json
    "ConnectionStrings": {
      "DefaultConnection": "Data Source=(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=localhost)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=ORCL)));User Id=HealthAdmin;Password=Password123;"
    }
    ```
    *   **HOST**: Your Oracle DB hostname (e.g., `localhost`).
    *   **PORT**: Your Oracle DB port (default `1521`).
    *   **User Id**: Your Oracle DB username.
    *   **Password**: Your Oracle DB password.

### Apply Migrations

To create the database schema, apply the Entity Framework migrations.

1.  Install the EF Core tool (if not already installed):
    ```bash
    dotnet tool install --global dotnet-ef
    ```

2.  Run the database update command from the project root:
    ```bash
    dotnet ef database update --project src/HealthCorp.Infrastructure --startup-project src/HealthCorp.Web
    ```

    *Note: If this is the first time running, you may need to add an initial migration first:*
    ```bash
    dotnet ef migrations add InitialCreate --project src/HealthCorp.Infrastructure --startup-project src/HealthCorp.Web
    ```

## 5. Execution

To run the web application:

1.  Navigate to the Web project directory or run from root:

    ```bash
    dotnet run --project src/HealthCorp.Web
    ```

2.  The application will start and listen on the configured ports (usually `http://localhost:5000` or `https://localhost:5001`). Check the console output for the exact URL.

3.  Open your web browser and navigate to the displayed URL.

## 6. Usage & Default Credentials

The database is seeded with a default administrator account.

*   **Login Page**: Click "Login" in the navigation bar.
*   **Username**: `admin`
*   **Password**: `admin123`

Once logged in, you can access the Patient Management, Appointment Scheduling, and Medical Records upload features.

## 7. Known Vulnerabilities for Training

This application contains intentional vulnerabilities for educational purposes, including:
*   SQL Injection
*   Authentication Bypass
*   IDOR (Insecure Direct Object References)
*   Sensitive Data Exposure
*   Race Conditions
*   SSRF (Server-Side Request Forgery)
*   Insecure Deserialization
*   File Upload Vulnerabilities

**DO NOT DEPLOY THIS APPLICATION TO A PRODUCTION ENVIRONMENT.**
