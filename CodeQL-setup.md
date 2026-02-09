# CodeQL Setup for ASP.NET / ASP.NET Core on Windows

### (From Download → Environment Setup → Required Rules)

---

## 1. Downloading CodeQL (Official & Safe Way)

### 1.1 Official download source

CodeQL CLI is maintained by GitHub and **must only be downloaded from the official repository**:

👉 **[https://github.com/github/codeql-cli-binaries/releases](https://github.com/github/codeql-cli-binaries/releases)**

Download the latest stable Windows build:

```
codeql-win64.zip
```

Do **not** download CodeQL from third-party sites.

---

## 2. Extracting CodeQL on Windows

### 2.1 Create a dedicated directory

Recommended location:

```
C:\codeql
```

### 2.2 Extract the ZIP

Extract `codeql-win64.zip` directly into `C:\codeql`.

After extraction, the folder **must** look like this:

```
C:\codeql\
 ├─ codeql.exe
 ├─ tools\
 ├─ qlpacks\
```

If `codeql.exe` is nested deeper (for example `C:\codeql\codeql\codeql.exe`), extraction is incorrect and CodeQL will not work properly.

---

## 3. Add CodeQL to PATH (Windows GUI – Recommended)

### 3.1 Open Environment Variables

1. Press **Win + R**
2. Type `sysdm.cpl`
3. Press Enter
4. Go to the **Advanced** tab
5. Click **Environment Variables**

---

### 3.2 Update System PATH

1. Under **System variables**, select `Path`
2. Click **Edit**
3. Click **New**
4. Add:

```
C:\codeql
```

5. Click **OK** on all windows

⚠️ Close **all** PowerShell / CMD windows and open a new one.

---

### 3.3 Verify installation

Open PowerShell and run:

```powershell
codeql version
```

You should see the CodeQL version printed.
If not, PATH is not set correctly.

---

## 4. Required Environment Variable for ASP.NET (.NET 6/7/8)

### 4.1 Why this is mandatory

On modern .NET versions, CodeQL **cannot intercept the C# compiler** unless MSBuild mode is forced.

Without this, you will see:

> “CodeQL detected code written in C# but could not process any of it”

---

### 4.2 Set the required environment variable (GUI or CLI)

#### Option A: Using PowerShell

```powershell
setx CODEQL_EXTRACTOR_CSHARP_BUILD_MODE msbuild
```

#### Option B: Using Windows GUI

1. Open **Environment Variables**
2. Under **System variables**, click **New**
3. Name:

```
CODEQL_EXTRACTOR_CSHARP_BUILD_MODE
```

4. Value:

```
msbuild
```

5. Click OK and **restart PowerShell**

✅ This was the **final fix** that allowed the database to be created successfully.

---

## 5. Required CodeQL Rules for ASP.NET Applications

Not all CodeQL rules are equally useful.
Below are the **high-signal rules** you should always include for ASP.NET / ASP.NET Core.

---

### 5.1 Critical Injection & RCE Rules (Must-Have)

| Rule ID                     | Vulnerability             | CWE    |
| --------------------------- | ------------------------- | ------ |
| `cs/sql-injection`          | SQL Injection             | CWE-89 |
| `cs/web/xss`                | Cross-Site Scripting      | CWE-79 |
| `cs/command-line-injection` | OS Command Injection      | CWE-78 |
| `cs/zipslip`                | Zip Slip / Path Traversal | CWE-22 |
| `cs/path-injection`         | File Path Injection       | CWE-22 |

---

### 5.2 Auth, Session & Web Security Rules

| Rule ID                                 | Risk              |
| --------------------------------------- | ----------------- |
| `cs/web/missing-antiforgery-validation` | CSRF              |
| `cs/web/insecure-cookie`                | Session hijacking |
| `cs/open-redirect`                      | Open redirect     |

---

### 5.3 Secrets & Cryptography Rules

| Rule ID                    | Risk               |
| -------------------------- | ------------------ |
| `cs/hardcoded-credentials` | Hardcoded secrets  |
| `cs/weak-crypto`           | Weak encryption    |
| `cs/insecure-randomness`   | Predictable tokens |

---

### 5.4 Official Query Pack (Recommended)

Always use the official pack:

```powershell
codeql pack download codeql/csharp-queries
```

Run analysis:

```powershell
codeql database analyze codeql-db `
  codeql/csharp-queries `
  --format=sarifv2.1.0 `
  --output=results.sarif
```

---

## 6. Final Notes (Important)

* CodeQL **does not scan dependencies** (NuGet CVEs are separate)
* Build success ≠ CodeQL extraction success
* ASP.NET Core **requires MSBuild mode**
* This setup is valid for:

  * MVC
  * Razor Pages
  * Minimal APIs
  * .NET 6 / 7 / 8

---
## Run Your First CodeQL Project (project1) — Short Guide

### 1. Directory structure (important)

Keep **CodeQL DB inside the project root**.

```
C:\codeql-work\
 └─ project1\
    ├─ project1.csproj
    ├─ Program.cs
    ├─ Controllers\
    ├─ bin\
    ├─ obj\
    └─ codeql-db\   (created by CodeQL)
```

Always run CodeQL commands **from inside `project1` folder**.

---

### 2. Open PowerShell in project folder

```powershell
cd C:\codeql-work\project1
```

---

### 3. One-time prerequisite (already done, just reminder)

```powershell
setx CODEQL_EXTRACTOR_CSHARP_BUILD_MODE msbuild
```

Close PowerShell and reopen.

---

### 4. Clean the project (recommended)

```powershell
dotnet clean
rmdir /s /q bin
rmdir /s /q obj
```

---

### 5. Create CodeQL database (main command)

```powershell
codeql database create codeql-db `
  --language=csharp `
  --command="dotnet build -c Debug --no-incremental /p:UseSharedCompilation=false /p:UseRazorBuildServer=false" `
  --source-root=. `
  --overwrite
```

If this succeeds → **extraction worked** 

---

### 6. Run analysis

```powershell
codeql database analyze codeql-db `
  codeql/csharp-queries `
  --format=sarifv2.1.0 `
  --output=results.sarif
```

---

### 7. View results (clickable findings)

1. Open **VS Code**
2. Install **SARIF Viewer** extension
3. Open `results.sarif`
4. Click issues → jump to code

---

### TL;DR

* Project folder = `project1`
* Run CodeQL **from project root**
* DB folder = `project1\codeql-db`
* Always disable incremental + build servers
* Use SARIF Viewer to click findings
