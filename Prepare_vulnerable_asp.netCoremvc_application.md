
# 🔥 MASTER PROMPT: Vulnerable ASP.NET + Oracle CTF App

```
You are a senior enterprise ASP.NET architect and an offensive security engineer.

Your task is to DESIGN AND IMPLEMENT a deliberately vulnerable, production-realistic web application to be used as a Capture-The-Flag (CTF) and secure code review training platform.

The application MUST look like a real healthcare enterprise system written by multiple teams over time.

==============================
CORE TECHNOLOGY REQUIREMENTS
==============================

• Framework:
  - ASP.NET Core (latest stable)
  - Mix of ASP.NET Core MVC and ASP.NET Core Web API
  - Realistic folder structure (Controllers, Services, Repositories, Middleware, DTOs, Legacy)

• Database:
  - Oracle Database
  - Mix of:
    - Entity Framework Core (Oracle provider)
    - Raw SQL using Oracle.ManagedDataAccess
  - Use Oracle-specific SQL syntax and quirks (DUAL, NVL, TO_CHAR, ROWNUM, implicit conversions)

• Architecture:
  - Partial layered architecture (Controllers → Services → Data)
  - Intentionally broken abstractions in some areas
  - Mix of async/await and sync code
  - Some legacy static helper classes

==============================
APPLICATION DOMAIN
==============================

Healthcare system with features like:
• Patient management
• Appointment scheduling
• Medical reports
• File uploads (lab reports, scans)
• Admin & staff portal

Roles:
• Admin
• Manager
• User (Doctor / Staff)

Include:
• Audit logging (intentionally flawed)
• File uploads
• Report export endpoints
• Email / notification simulation (no real SMTP)

==============================
VULNERABILITY DESIGN (CRITICAL)
==============================

For EACH vulnerability category listed below, implement TWO versions:

1. EASY VERSION
   - Clearly vulnerable
   - Can be found by SAST and beginner reviewers
   - Usually localized in one file

2. HARD VERSION
   - Spread across multiple files / layers
   - Appears secure at first glance
   - Often passes data through DTOs, services, helpers
   - Uses misleading variable names and defensive-looking code
   - May require tracing async flows
   - May require Oracle SQL knowledge
   - Often MISSES SAST and basic DAST
   - Discoverable by humans doing deep review or logic analysis

==============================
REQUIRED VULNERABILITY TYPES
==============================

Implement BOTH easy and hard versions of ALL below:

• SQL Injection
  - Oracle-specific injection patterns
  - Implicit conversions, dynamic ORDER BY, concatenated WHERE clauses

• Authentication bypass
  - Token misuse
  - Legacy auth fallback logic

• Broken access control
  - IDOR
  - Role confusion between Admin / Manager
  - Trusting client-side role claims

• Insecure deserialization
  - JSON and binary formatter misuse
  - Hidden behind helper utilities

• File upload vulnerabilities
  - Extension validation bypass
  - Content-type trust
  - Path traversal in Oracle-stored metadata

• SSRF
  - URL fetch for medical image preview
  - DNS-based bypasses

• XSS
  - Stored, reflected, and DOM-like patterns
  - Razor + API response interaction

• CSRF
  - Missing or misapplied anti-forgery tokens
  - Custom middleware mistakes

• Business logic flaws
  - Appointment double-booking
  - Unauthorized report access via workflow abuse

• Cryptographic misuse
  - Weak hashing
  - Static keys
  - Incorrect use of ASP.NET data protection APIs

• Secrets in code / config
  - Hardcoded Oracle credentials
  - API keys in appsettings and legacy classes

• Dependency vulnerabilities (SCA)
  - Outdated NuGet packages
  - Known vulnerable libraries with justification comments

• Race conditions
  - Async appointment booking
  - TOCTOU issues

• Logging & monitoring failures
  - Sensitive data logged
  - Missing logs for security-critical actions

==============================
NON-OWASP & PLATFORM-SPECIFIC ISSUES
==============================

Include:
• Oracle-specific SQL anti-patterns
• ASP.NET middleware misordering
• Identity misconfiguration
• Legacy authentication mixed with modern Identity

==============================
DETECTION & CTF DESIGN
==============================

• Some vulnerabilities should:
  - Be detectable by SAST
  - Be missed by SAST but found by humans
  - Only be exploitable via runtime behavior (DAST)
  - Fool both SAST & DAST unless logic is understood

• Some vulnerabilities must:
  - Only trigger under specific runtime conditions
  - Require chaining multiple issues

==============================
CTF MECHANICS
==============================

• No flags visible in source code
• Vulnerabilities award points when exploited (describe conceptually)
• Assume instructor validates exploitation externally

==============================
REALISM REQUIREMENTS
==============================

• Mix of clean modern code and ugly legacy code
• Comments showing “secure intent” but flawed execution
• TODOs, refactors, and tech debt
• Naming that looks professional, not CTF-ish

==============================
ETHICS & BOUNDARIES
==============================

• Include RCE vulnerabilities
• Include malware-like payload paths
• Do NOT include real malware binaries
• Everything must remain educational and contained

==============================
OUTPUT REQUIREMENTS
==============================

1. Full project structure
2. Key code files (Controllers, Services, Repositories, Middleware)
3. appsettings.json with issues
4. Oracle schema and sample SQL
5. Brief instructor notes explaining:
   - Easy vs hard version of each vulnerability
   - Why scanners might miss the hard version

DO NOT explain how to exploit step-by-step.
DO NOT label vulnerabilities explicitly in code.
The goal is realistic secure code review training.
```

---

## How to Use This Prompt (Important)

To get **maximum quality** from a coding LLM:

1. **Paste the prompt**
2. Then say:

   ```
   Generate the project incrementally.
   Start with architecture and folder structure.
   Wait for confirmation before generating full code.
   ```
3. Generate in stages:

   * Structure
   * Auth & identity
   * Data access
   * Vulnerable features
   * Instructor notes

This prevents the model from rushing and keeps realism high.


Say the word.
This CTF is going to hurt feelings — in the best educational way 😈
