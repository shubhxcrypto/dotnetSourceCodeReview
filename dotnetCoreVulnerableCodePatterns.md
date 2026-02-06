

# 🧨 Attack #1: SQL Injection in ASP.NET Core (Oracle-flavored)

This is *not* just `"... WHERE id = " + userInput`.
We’ll go from **obvious → sneaky → “looks secure” → enterprise-real**.

I’ll show **multiple vulnerable patterns**, explain *why they happen*, *why tools miss them*, and *what reviewers should mentally flag*.

---

## 🟢 Pattern 1: Obvious String Concatenation (Easy / SAST Candy)

### Code

```csharp
public Patient GetPatient(string patientId)
{
    using var conn = new OracleConnection(_connString);
    conn.Open();

    var sql = "SELECT * FROM PATIENTS WHERE PATIENT_ID = '" + patientId + "'";
    using var cmd = new OracleCommand(sql, conn);

    using var reader = cmd.ExecuteReader();
    ...
}
```

### Why it’s vulnerable

* Direct concatenation
* Quotes included
* Oracle happily executes injected payloads

### Why scanners find it

* Literal `+ userInput`
* Classic signature

### Reviewer instinct

🚩 *Any SQL with quotes + input = stop reading, already bad*

---

## 🟡 Pattern 2: “But I validated it!” (False Sense of Security)

### Code

```csharp
public Patient GetPatient(string patientId)
{
    if (!Regex.IsMatch(patientId, "^[A-Z0-9]+$"))
        throw new ArgumentException();

    var sql = $"SELECT * FROM PATIENTS WHERE PATIENT_ID = '{patientId}'";
    ...
}
```

### Why it’s still vulnerable

* Validation ≠ escaping
* Regex assumptions break over time
* Oracle implicit conversions (`TO_CHAR`, `NVL`) can bypass

### Why SAST might still catch it

* Interpolation inside SQL string

### Why humans should care

* Dev *thought* they fixed it
* These survive code reviews surprisingly often

🧠 **Reviewer thought**:

> “Why is this not a bind variable?”

---

## 🟠 Pattern 3: Dynamic ORDER BY (Very Common, Often Missed)

### Code

```csharp
public IEnumerable<Patient> Search(string sortBy)
{
    var sql = $@"
        SELECT * FROM PATIENTS
        ORDER BY {sortBy}
    ";

    return _repo.Query(sql);
}
```

### Why this is dangerous

* ORDER BY **cannot** be parameterized
* Attackers inject expressions, subqueries, functions

Oracle examples:

```sql
CASE WHEN (SELECT COUNT(*) FROM USERS)>0 THEN NAME END
```

### Why scanners miss it

* No quotes
* No obvious `WHERE`
* Looks like metadata, not data

### Reviewer instinct

🚩 *Any dynamic SQL fragment = threat model immediately*

---

## 🔴 Pattern 4: “Parameterized” But Not Really (Oracle Trap)

### Code

```csharp
var sql = @"
    SELECT * FROM PATIENTS
    WHERE PATIENT_ID = :id
";

cmd.CommandText = sql;
cmd.Parameters.Add($":{columnName}", patientId);
```

### What’s wrong

* Parameter name is dynamic
* Oracle binds **positionally**, not logically
* Column name still user-controlled

### Why SAST often misses it

* Sees parameters
* Thinks it’s safe

### Reviewer instinct

🧠 *Are both sides of the comparison trusted?*

---

## 🔥 Pattern 5: EF Core + Raw SQL Combo (Real Enterprise Bug)

### Code

```csharp
public IEnumerable<Patient> GetPatients(string filter)
{
    var sql = $@"
        SELECT * FROM PATIENTS
        WHERE STATUS = 'ACTIVE'
        {filter}
    ";

    return _dbContext.Patients
        .FromSqlRaw(sql)
        .AsNoTracking()
        .ToList();
}
```

### Why this is nasty

* EF Core gives a **false sense of safety**
* `filter` often comes from:

  * UI advanced search
  * Admin-only features
* Attack surface widens silently

### Why tools miss it

* EF Core = “ORM = safe”
* Filter might originate 3 layers up

### Reviewer instinct

🚨 *FromSqlRaw + string interpolation = stop everything*

---

## ☠️ Pattern 6: “Safe” Stored Procedure Abuse (Oracle-Specific)

### Code

```csharp
cmd.CommandType = CommandType.StoredProcedure;
cmd.CommandText = "SEARCH_PATIENTS";

cmd.Parameters.Add("P_FILTER", userInput);
```

### Oracle procedure

```sql
EXECUTE IMMEDIATE
  'SELECT * FROM PATIENTS WHERE ' || P_FILTER;
```

### Why this is brutal

* App code looks perfect
* Injection lives in DB
* Most SAST tools **never see PL/SQL**

### Reviewer instinct

🧠 *What does the procedure do internally?*

---

## 🧩 Pattern 7: Injection via Business Logic (Hard Version)

### Code path

```
Controller → DTO → Service → Rule Engine → SQL Builder
```

### Example

```csharp
if (request.IncludeArchived)
    sql += " OR ARCHIVED = 1";
```

Attacker controls:

```json
{
  "includeArchived": "1=1 --"
}
```

### Why this survives reviews

* Looks like boolean logic
* No quotes
* Happens deep in code

### Reviewer instinct

🧠 *Where did this boolean originate?*

---

## 🎯 Reviewer Mental Checklist (SQLi)

When reviewing ASP.NET Core:

Ask **every time**:

* Where did this value originate?
* Is this *data* or *SQL structure*?
* Can Oracle reinterpret this?
* Is EF Core actually bypassed here?
* Does a stored procedure hide dynamic SQL?

# 🔓 Attack #2: Authentication Bypass in ASP.NET Core

Before code, let’s align on **the idea**.

---

## 🧠 Mental Model (Read This First)

**Authentication bypass** means:

> The application thinks the user is logged in — but they should not be.

This usually does **NOT** mean:

* broken passwords
* weak hashing

It usually **DOES** mean:

* trusting the wrong thing
* fallback logic
* “temporary” legacy behavior
* middleware doing things in the wrong order

In ASP.NET Core, auth is mostly about:

1. **Middleware order**
2. **Claims**
3. **Tokens**
4. **Context (`HttpContext.User`)**

If *any* of these are wrong → bypass.

---

## Pattern 1: Trusting a Claim Without Verifying Authentication (EASY)

### What the developer wanted

> “If the user has an Admin role, allow access.”

### Code

```csharp
public IActionResult AdminDashboard()
{
    if (User.HasClaim("role", "Admin"))
    {
        return View();
    }

    return Unauthorized();
}
```

### Why this feels reasonable

* Uses `User`
* Uses claims
* Looks like standard ASP.NET Core

### What is actually missing

❌ **No check that the user is authenticated**

### What goes wrong

If *anything* adds a claim to `HttpContext.User`, this passes — even if:

* no login happened
* token is fake
* middleware ran incorrectly

### Why scanners miss it

* No crypto
* No string comparison with input
* Looks “framework-native”

### Reviewer mental trigger

🧠

> “Where does this claim come from, and who put it there?”

---

## Pattern 2: Legacy Header-Based Auth (Very Real)

### What the developer wanted

> “Support old internal systems while migrating to JWT.”

### Code

```csharp
public async Task Invoke(HttpContext context)
{
    if (context.Request.Headers.ContainsKey("X-User"))
    {
        var identity = new ClaimsIdentity("Legacy");
        identity.AddClaim(new Claim(ClaimTypes.Name,
            context.Request.Headers["X-User"]));
        identity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));

        context.User = new ClaimsPrincipal(identity);
    }

    await _next(context);
}
```

### Why devs write this

* Internal network
* “Trusted” systems
* Migration pressure

### What actually happens

Anyone who can send:

```
X-User: attacker
```

→ becomes **Admin**

### Why this bypasses auth

* No password
* No token
* No signature
* Claim is *self-issued*

### Why tools miss it

* No known vuln signature
* Middleware looks legit

### Reviewer mental trigger

🧠

> “Is this identity *proven* or just *asserted*?”

---

## Pattern 3: Fallback Authentication Logic (Harder)

### What the developer wanted

> “If JWT fails, try cookie auth.”

### Code

```csharp
if (!context.User.Identity.IsAuthenticated)
{
    await context.AuthenticateAsync("Cookies");
}
```

### Why this feels safe

* Uses framework auth
* Has multiple schemes
* Defensive-looking

### What goes wrong

If:

* cookie auth is misconfigured
* cookie is unsigned
* cookie is stale

→ User becomes authenticated **without login**

### Why scanners miss it

* Uses official APIs
* No unsafe calls

### Reviewer mental trigger

🧠

> “Why is fallback allowed at all?”

---

## Pattern 4: Middleware Order Mistake (Classic ASP.NET Core Bug)

### Correct order

```csharp
app.UseAuthentication();
app.UseAuthorization();
```

### Vulnerable order

```csharp
app.UseAuthorization();
app.UseAuthentication();
```

### Why this breaks security

* Authorization runs first
* `User` is still empty
* Policies behave unpredictably
* Custom authorization logic may allow access

### Why this is dangerous

* No code change needed
* Happens during refactor
* Looks harmless

### Why scanners miss it

* Requires understanding request pipeline
* Static analysis rarely models middleware order

### Reviewer mental trigger

🧠

> “Is User populated before authorization runs?”

---

## Pattern 5: JWT Validation Without Signature Check (HARD)

### What the developer wanted

> “Just read claims from the token.”

### Code

```csharp
var handler = new JwtSecurityTokenHandler();
var token = handler.ReadJwtToken(jwt);

var username = token.Claims.First(c => c.Type == "sub").Value;
```

### What is missing

❌ Signature validation
❌ Issuer validation
❌ Audience validation

### What attacker does

* Creates **any JWT**
* Sets:

```json
{
  "sub": "admin",
  "role": "Admin"
}
```

### Why this survives reviews

* Uses JWT classes
* No obvious “bad code”
* Dev thinks parsing = validation

### Reviewer mental trigger

🧠

> “Where is the token actually validated?”

---

## Pattern 6: “Temporary” Debug Bypass (Enterprise Reality)

### Code

```csharp
if (_env.IsDevelopment())
{
    context.User = TestUsers.Admin;
}
```

### Why this becomes exploitable

* Environment misconfigured
* Dev forgets to remove it
* Feature flag leaks to prod

### Reviewer mental trigger

🧠

> “Can this condition ever be true in prod?”

---

## 🧠 One Simple Rule for Reviewers

When reviewing authentication code, **ignore the framework** and ask:

> ❓ Who *proved* this user’s identity?
> ❓ What *cryptographic check* happened?
> ❓ What would happen if I send my own request?

If you cannot point to **the exact line** where identity is proven → assume bypass.

---

## Why This Is Hard to Detect

* Looks “standard”
* Uses framework APIs
* No obvious user input
* Often spread across middleware + controllers

---

# 🧾 Attack #3: Broken Access Control / IDOR (ASP.NET Core)

This is one of the **most important** vulnerabilities for:

* source code review
* real-world pentesting
* CTF design

And it’s *often missed* because the code looks “clean”.

---

## 🧠 Mental Model (Very Important)

**Access control answers ONE question only:**

> “Is this user allowed to access *this specific resource*?”

❌ It is **NOT**:

* “Is the user logged in?”
* “Is the user an admin?”

IDOR happens when:

> The app checks **who you are**, but not **what you’re accessing**.

---

## Pattern 1: Classic IDOR (EASY)

### What the developer wanted

> “Let users view their appointment details.”

### Code

```csharp
[Authorize]
public IActionResult AppointmentDetails(int appointmentId)
{
    var appointment = _db.Appointments
        .FirstOrDefault(a => a.Id == appointmentId);

    return View(appointment);
}
```

### Why this looks fine

* `[Authorize]` present
* Uses database
* No obvious vulnerability

### What is missing

❌ No ownership check

### What attacker does

```
/appointments/details?appointmentId=123
```

→ changes `123` to another ID

### Reviewer mental trigger

🧠

> “How do we know this appointment belongs to *this* user?”

---

## Pattern 2: Role Check Without Resource Check

### What the developer wanted

> “Only Doctors can view reports.”

### Code

```csharp
[Authorize(Roles = "Doctor")]
public IActionResult ViewReport(int reportId)
{
    var report = _repo.GetReport(reportId);
    return View(report);
}
```

### What’s wrong

* Role is checked
* Resource ownership is not

### Result

Any doctor can view **any patient’s report**

### Why scanners miss it

* Authorization attribute exists
* No obvious misuse

### Reviewer mental trigger

🧠

> “Doctor of *which patient*?”

---

## Pattern 3: Secure DTO Illusion (HARDER)

### What the developer wanted

> “Expose only safe fields.”

### Code

```csharp
public class AppointmentDto
{
    public int Id { get; set; }
    public DateTime Time { get; set; }
}
```

Controller:

```csharp
public IActionResult GetAppointment(int id)
{
    var appt = _service.GetAppointment(id);
    return Ok(appt);
}
```

Service:

```csharp
public AppointmentDto GetAppointment(int id)
{
    var entity = _repo.Find(id);
    return _mapper.Map<AppointmentDto>(entity);
}
```

### Why devs feel safe

* DTO hides sensitive data
* Clean architecture

### What’s still broken

❌ No access check anywhere

DTOs **do not enforce authorization**

### Reviewer mental trigger

🧠

> “Where is the permission decision made?”

---

## Pattern 4: Client-Controlled User ID (Very Common)

### What the developer wanted

> “Admin can act on behalf of users.”

### Code

```csharp
public IActionResult GetUserAppointments(int userId)
{
    return Ok(_repo.GetAppointments(userId));
}
```

### What attacker does

Just changes `userId`

### Why this happens

* Trust in UI
* Assumption that only admins call this

### Why tools miss it

* No tainted input usage
* Business logic issue

### Reviewer mental trigger

🧠

> “Why does the client tell us who they are?”

---

## Pattern 5: “Admin OR Owner” Logic Bug (HARD)

### Code

```csharp
if (User.IsInRole("Admin") || appointment.UserId == userId)
{
    return View(appointment);
}
```

### What looks correct

* Admin allowed
* Owner allowed

### What’s wrong

Where did `userId` come from?

If it came from:

* route
* query
* body

→ attacker sets it to match

### Reviewer mental trigger

🧠

> “Is this identity derived from server-side truth?”

---

## Pattern 6: Access Control Split Across Layers (Very Real)

### Flow

```
Controller → Service → Repository
```

Controller:

```csharp
[Authorize]
public IActionResult DownloadReport(int id)
{
    return File(_service.GetReportFile(id));
}
```

Service:

```csharp
public byte[] GetReportFile(int id)
{
    return _repo.GetFile(id);
}
```

Repository:

```csharp
public byte[] GetFile(int id)
{
    return _db.Reports.Find(id).File;
}
```

### What happened

❌ No layer checks authorization

Each layer assumes the other handled it.

### Reviewer mental trigger

🧠

> “Where is the *single source of truth* for authorization?”

---

## Pattern 7: Async Timing / Race Condition IDOR (ADVANCED)

### Scenario

* Appointment approval
* Status changes async

### Code

```csharp
if (appointment.Status == "Pending")
{
    await _repo.ApproveAsync(id);
}
```

Attacker:

* Rapidly accesses before status updates
* Gets access to restricted data

### Why this is hard

* Timing dependent
* No obvious missing check

### Reviewer mental trigger

🧠

> “Can state change between check and use?”

---

## 🧠 One Rule That Catches 90% of IDOR

For every endpoint, ask:

> ❓ What resource is being accessed?
> ❓ Who owns it?
> ❓ Where is that relationship enforced?

If the answer is:

* “UI prevents it”
* “DTO hides it”
* “Service probably checks it”

→ it’s broken.

---

## Why IDOR Is Perfect for CTFs

* Easy version: missing ownership check
* Hard version: split logic, async flows
* Scanners usually fail
* Humans learn *real* review skills



# 📦 Attack #4: Insecure Deserialization (ASP.NET Core)

This one is tricky because **ASP.NET Core is mostly safe by default**, so when it *does* appear, it’s usually:

* custom code
* legacy helpers
* “clever” abstractions
* performance hacks

---

## 🧠 Mental Model (Read Carefully)

**Serialization** = converting an object to bytes/text
**Deserialization** = converting bytes/text back to an object

👉 Insecure deserialization happens when:

> The application accepts serialized data from the user
> and turns it into an object
> **without controlling what type is created or how it behaves**

The danger is **not the data**
The danger is **the object type and its side effects**

---

## Pattern 1: Trusting User-Controlled JSON Type (EASY)

### What the developer wanted

> “Support multiple request types dynamically.”

### Code

```csharp
public IActionResult Process([FromBody] JsonElement payload)
{
    var typeName = payload.GetProperty("type").GetString();
    var data = payload.GetProperty("data").ToString();

    var type = Type.GetType(typeName);
    var obj = JsonSerializer.Deserialize(data, type);

    _handler.Handle(obj);
    return Ok();
}
```

### Why this feels flexible

* Generic
* Reusable
* Avoids many endpoints

### What goes wrong

Attacker controls:

* `typeName`
* object structure

If **any type** in the app:

* executes code in constructor
* overrides `OnDeserialized`
* triggers file/network actions

→ execution happens

### Reviewer mental trigger

🧠

> “Who controls the type being deserialized?”

---

## Pattern 2: BinaryFormatter (Still Exists in Legacy Code)

### Code

```csharp
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream);
```

### Why this is always dangerous

* Allows arbitrary type creation
* Constructors run automatically
* .NET ecosystem has many “gadget” types

### Why this still appears

* Old .NET Framework code
* Migrated into .NET Core
* “Temporary” backward compatibility

### Reviewer mental trigger

🧠

> “Why does this need binary deserialization at all?”

(Answer is almost always: it doesn’t.)

---

## Pattern 3: Safe-Looking JSON with Polymorphism (HARDER)

### What the developer wanted

> “Support different notification types.”

### Code

```csharp
public class Notification
{
    public string Message { get; set; }
}

public class EmailNotification : Notification
{
    public string SmtpServer { get; set; }
}
```

Config:

```csharp
options.JsonSerializerOptions.TypeInfoResolver =
    new DefaultJsonTypeInfoResolver
    {
        Modifiers =
        {
            PolymorphismOptions =
            {
                TypeDiscriminatorPropertyName = "$type"
            }
        }
    };
```

Payload:

```json
{
  "$type": "EmailNotification",
  "smtpServer": "attacker.com"
}
```

### Why this is dangerous

* Polymorphism enables type selection
* Attackers select unexpected derived types
* Side effects may occur during processing

### Why tools miss it

* JSON only
* No reflection code
* Looks “modern”

### Reviewer mental trigger

🧠

> “Are all derived types safe?”

---

## Pattern 4: Deserialization Hidden in Helpers (Very Real)

### Code

```csharp
public static T Load<T>(string base64)
{
    var bytes = Convert.FromBase64String(base64);
    return JsonSerializer.Deserialize<T>(bytes);
}
```

Controller:

```csharp
var settings = SettingsLoader.Load<AppSettings>(input);
```

### Why this is dangerous

* Deserialization abstracted away
* Reviewer sees only `Load<T>`
* Input origin unclear

### What can go wrong

* `T` becomes more complex later
* New properties added with side effects
* Attack surface grows silently

### Reviewer mental trigger

🧠

> “What assumptions does this helper make?”

---

## Pattern 5: Deserialization + Dependency Injection (ADVANCED)

### Code

```csharp
var obj = JsonSerializer.Deserialize(json, type);
_services.GetService(type);
```

### Why this is scary

* Object type controls DI resolution
* Can trigger:

  * file access
  * HTTP clients
  * background tasks

### Why scanners miss it

* No dangerous API
* Requires understanding DI behavior

### Reviewer mental trigger

🧠

> “Can deserialized objects trigger framework behavior?”

---

## Pattern 6: Cached Serialized Objects (Enterprise Bug)

### What the developer wanted

> “Improve performance.”

### Code

```csharp
cache.Set(key, JsonSerializer.Serialize(obj));
```

Later:

```csharp
var obj = JsonSerializer.Deserialize<Config>(cacheValue);
```

### What goes wrong

If attacker can:

* poison cache
* control key generation

→ poisoned objects reloaded later

### Reviewer mental trigger

🧠

> “Can attackers influence cached serialized data?”

---

## 🧠 One Rule That Catches This Class

Ask ONE question:

> ❓ Can the attacker influence **what type** is deserialized?

If yes → vulnerability likely exists.

---

## Why This Is Great for CTFs

* Easy version: `Type.GetType()` deserialization
* Hard version: polymorphism + helpers
* Requires source tracing
* Scanners often miss


---

# 📁➡️💥 Attack #5: File Upload → RCE (ASP.NET Core)

This is a **chain attack**.
On its own, file upload often looks harmless.
RCE happens when **multiple small mistakes connect**.

So we’ll think in **layers**, not one bug.

---

## 🧠 Mental Model (Very Important)

File upload vulnerabilities are **not about uploading a file**.

They are about:

1. **Where the file is stored**
2. **How the file is named**
3. **How the file is later used**
4. **Who controls that usage**

👉 RCE happens when:

> An attacker uploads a file
> AND the application later **executes, parses, or loads** it

---

## Step 0: What Developers *Think* They’re Doing

> “Users upload medical reports (PDF, images).
> We save them and later show/download them.”

That sounds safe.
The danger is in the **details**.

---

## Pattern 1: Extension-Based Validation (EASY)

### Developer intention

> “Allow only PDFs.”

### Code

```csharp
if (!file.FileName.EndsWith(".pdf"))
{
    return BadRequest("Invalid file");
}

var path = Path.Combine("uploads", file.FileName);
using var fs = new FileStream(path, FileMode.Create);
await file.CopyToAsync(fs);
```

### Why this is broken

* File extension is **user-controlled**
* `report.pdf.exe`
* `report.pdf.aspx`
* `report.pdf;.aspx` (Windows quirks)

### Why this matters

If uploads are:

* served by the app
* under `wwwroot`

→ uploaded code may execute

### Reviewer mental trigger

🧠

> “Is extension the *only* check?”

---

## Pattern 2: Content-Type Trust (Very Common)

### Code

```csharp
if (file.ContentType != "application/pdf")
{
    return BadRequest();
}
```

### Why this is meaningless

* `Content-Type` is a **header**
* Attacker sets it manually

### Why scanners miss it

* Looks like validation
* No dangerous API

### Reviewer mental trigger

🧠

> “Who sets Content-Type?”

(Answer: the attacker.)

---

## Pattern 3: Uploads Inside wwwroot (Critical)

### Code

```csharp
var uploadPath = Path.Combine(
    _env.WebRootPath,
    "uploads",
    file.FileName
);
```

### Why this is dangerous

* `wwwroot` = web-accessible
* If file is:

  * `.aspx`
  * `.cshtml`
  * `.dll`

→ it may execute or be interpreted

### Result

```
https://app/uploads/shell.aspx
```

### Reviewer mental trigger

🧠

> “Can uploaded files be requested directly?”

---

## Pattern 4: File Name Trust (Path Traversal)

### Code

```csharp
var path = Path.Combine("uploads", file.FileName);
```

### Attacker supplies

```
../../../../appsettings.json
```

### Result

* Overwrites config
* Drops payload in sensitive location

### Why devs miss this

* `Path.Combine` feels safe
* It is not a sanitizer

### Reviewer mental trigger

🧠

> “Is filename normalized or replaced?”

---

## Pattern 5: Virus Scan / AV Illusion (False Safety)

### Code

```csharp
if (_scanner.IsClean(file))
{
    Save(file);
}
```

### Why this fails

* Scanners miss:

  * script payloads
  * logic bombs
  * deserialization gadgets
* Scanner ≠ sandbox

### Reviewer mental trigger

🧠

> “What happens if a malicious file passes?”

---

## Pattern 6: File Upload → Deserialization → RCE (CHAIN)

### Developer intention

> “Store report metadata.”

### Code

```csharp
var meta = JsonSerializer.Deserialize<ReportMeta>(
    await new StreamReader(file.OpenReadStream()).ReadToEndAsync()
);
```

### What attacker uploads

A crafted JSON that:

* creates unexpected object graphs
* triggers dangerous behavior later

### Why this is powerful

* Upload looks safe
* RCE happens **later**
* Hard to trace

### Reviewer mental trigger

🧠

> “Is uploaded content ever parsed?”

---

## Pattern 7: Oracle Interaction (Enterprise-Real RCE)

### Code

```csharp
cmd.CommandText =
    "INSERT INTO FILES (NAME, PATH) VALUES (:n, :p)";
```

Later:

```sql
SELECT PATH FROM FILES WHERE ID = :id;
```

Then:

```csharp
Process.Start(path);
```

### What happens

* File path stored in DB
* Attacker controls path
* App executes it

### Why scanners miss it

* Execution happens far from upload
* Multi-layer chain

### Reviewer mental trigger

🧠

> “Is uploaded data ever executed or loaded?”

---

## Pattern 8: Temp File + Background Job (HARD)

### Flow

1. File uploaded
2. Saved to `/tmp`
3. Background job processes it

### Code

```csharp
Task.Run(() => ProcessFile(path));
```

### Why this is dangerous

* No validation at execution time
* File may change after upload
* TOCTOU race condition

### Reviewer mental trigger

🧠

> “Is the file revalidated before use?”

---

## 🧠 One Rule That Catches 90% of Upload Bugs

Ask **three questions**:

1. ❓ Where is the file stored?
2. ❓ Can the attacker control its name or content?
3. ❓ Is it ever executed, parsed, or loaded?

If the answer to #3 is **yes** → you’re very close to RCE.

---

## Why This Is Perfect for CTFs

* Easy version: `.aspx` in `wwwroot`
* Hard version: upload → DB → background job → execution
* Requires chaining
* Teaches *real-world* thinking


# 🌐 Attack #6: SSRF (Server-Side Request Forgery) in ASP.NET Core

SSRF is confusing at first because:

* no SQL
* no auth bug
* no obvious “dangerous” API

Yet it often leads to **internal access, credential theft, or RCE chains**.


## 🧠 Mental Model (Read This First)

**SSRF means:**

> The attacker makes **your server** send an HTTP request
> to a destination **the attacker controls or chooses**

Key point:

* The request comes **from the server**
* It can reach things users cannot

Examples:

* internal services
* cloud metadata
* admin panels
* localhost APIs

---

## Step 0: Why Developers Accidentally Create SSRF

Developers often add features like:

* “Fetch image from URL”
* “Preview external report”
* “Webhook validation”
* “Import data from partner system”

All of these **require server-side HTTP requests**.

---

## Pattern 1: Simple URL Fetch (EASY)

### Developer intention

> “Preview a medical image from a URL.”

### Code

```csharp
public async Task<IActionResult> Preview(string imageUrl)
{
    var client = new HttpClient();
    var data = await client.GetByteArrayAsync(imageUrl);

    return File(data, "image/jpeg");
}
```

### Why this is vulnerable

Attacker controls `imageUrl`.

They can send:

```
http://localhost:5000/admin
http://127.0.0.1/health
```

The server fetches it **internally**.

### Reviewer mental trigger

🧠

> “Why is the server making a request based on user input?”

---

## Pattern 2: “But We Validate the URL” (False Safety)

### Code

```csharp
if (!imageUrl.StartsWith("http"))
{
    return BadRequest();
}
```

### Why this fails

All of these still work:

```
http://localhost
http://127.0.0.1
http://[::1]
http://internal-service
```

Validation checks **format**, not **destination**.

### Reviewer mental trigger

🧠

> “What hosts are actually allowed?”

---

## Pattern 3: Allowlist Done Wrong (Common Mistake)

### Code

```csharp
if (!imageUrl.Contains("trusted.com"))
{
    return BadRequest();
}
```

### Attacker uses

```
http://trusted.com.attacker.com
```

### Why this is dangerous

* String checks ≠ URL parsing
* DNS tricks bypass naive checks

### Reviewer mental trigger

🧠

> “Is this validation semantic or just string-based?”

---

## Pattern 4: DNS Rebinding / Resolution Trick (HARDER)

### Flow

1. URL passes validation
2. DNS resolves to public IP
3. Later resolves to internal IP

### Code

```csharp
var response = await _client.GetAsync(url);
```

### Why this matters

* Validation happens **before** request
* Resolution happens **during** request

### Why scanners miss it

* Timing-based
* Network-dependent

### Reviewer mental trigger

🧠

> “Is DNS resolution controlled or cached?”

---

## Pattern 5: HttpClient Factory + Trust Assumption

### Code

```csharp
services.AddHttpClient("external");
```

Later:

```csharp
var client = _factory.CreateClient("external");
await client.GetAsync(userProvidedUrl);
```

### Why this is dangerous

* “Named client” feels safe
* Destination still user-controlled

### Reviewer mental trigger

🧠

> “Who controls the final URL?”

---

## Pattern 6: SSRF Hidden in Business Logic (Very Real)

### Scenario

> “Import lab result from partner system.”

### Code

```csharp
var baseUrl = _config.PartnerApi;
var url = $"{baseUrl}/reports/{id}";

await _client.GetAsync(url);
```

### What attacker controls

* `id`
* Possibly config via another bug

Results in:

```
http://partner/reports/../../admin
```

### Reviewer mental trigger

🧠

> “Is path concatenation safe here?”

---

## Pattern 7: Cloud / Internal Metadata Access (Advanced)

### Code

```csharp
await client.GetAsync("http://169.254.169.254/latest/meta-data/");
```

### Why this is serious

* Cloud credentials exposed
* Leads to full compromise

### Why SSRF is dangerous even without RCE

SSRF often becomes:

* credential theft
* lateral movement
* privilege escalation

### Reviewer mental trigger

🧠

> “Can this reach internal-only addresses?”

---

## Pattern 8: SSRF → File Read → RCE Chain (CTF Gold)

### Flow

1. SSRF fetches internal admin API
2. API returns file content
3. File contains secrets
4. Secrets lead to RCE

SSRF is often **not the final bug**.

---

## 🧠 One Rule That Catches SSRF

Ask:

> ❓ Can the attacker influence **where** the server sends a request?

If yes:

* SSRF likely exists
* Risk depends on network access

---

## Why SSRF Is Great for CTFs

* Easy version: direct URL fetch
* Hard version: indirect URL building
* Requires understanding infrastructure
* Often missed by scanners

Great, let’s do this one **very carefully** — this is the hardest category, and also the **most valuable** for real code review skills.

---

# 🧠 Attack #7: Business Logic Flaws (ASP.NET Core)

This is where scanners mostly fail
and **humans must think like the application**.

So we’ll go **slow**, with stories, not just code.

---

## 🧠 Mental Model (This Is the Key)

A **business logic flaw** is NOT:

* bad input validation
* missing auth attribute
* unsafe API usage

A business logic flaw is:

> The application behaves *exactly as coded*
> but the behavior violates real-world rules.

So the question is **never**:

> “Is the code secure?”

The question is:

> “Does this flow make sense in reality?”

---

## Step 0: Why Developers Create These Bugs

Developers usually:

* implement features one by one
* assume happy paths
* trust previous steps were enforced
* split logic across services

No one is *trying* to be insecure.

---

## Pattern 1: Appointment Double-Booking (EASY)

### Real-world rule

> A doctor cannot have two appointments at the same time.

### Code

```csharp
public async Task Book(Appointment a)
{
    await _repo.Insert(a);
}
```

### What’s missing

❌ No conflict check

### What attacker does

* Sends two requests at same time
* Both succeed

### Why scanners miss it

* No unsafe API
* No tainted input

### Reviewer mental trigger

🧠

> “What real-world rule should exist here?”

---

## Pattern 2: Check Then Act (Race Condition Logic Bug)

### Code

```csharp
if (!_repo.Exists(a.Time, a.DoctorId))
{
    await _repo.Insert(a);
}
```

### Why this is broken

* Check and insert are separate
* Parallel requests bypass check

### Result

* Double booking still possible

### Reviewer mental trigger

🧠

> “What happens under concurrent requests?”

---

## Pattern 3: Cancel → Refund Abuse (Very Common)

### Rule

> Refund only once.

### Code

```csharp
if (appointment.Status == "Cancelled")
{
    return;
}

_refundService.Refund(appointment);
appointment.Status = "Cancelled";
```

### What attacker does

* Sends multiple cancel requests quickly
* Refund happens multiple times

### Why this happens

* Status update happens **after** refund
* No transaction

### Reviewer mental trigger

🧠

> “Is state updated before irreversible actions?”

---

## Pattern 4: Trusting Client State (Classic)

### Code

```csharp
if (model.Price == expectedPrice)
{
    Charge(model.Price);
}
```

### What attacker does

* Modifies request
* Pays less

### Why this survives reviews

* UI enforces correct price
* Server trusts UI

### Reviewer mental trigger

🧠

> “Is this value recalculated server-side?”

---

## Pattern 5: Workflow Skipping (HARDER)

### Intended flow

```
Draft → Submitted → Approved → Published
```

### Code

```csharp
UpdateStatus(id, model.Status);
```

### What attacker does

Sets:

```json
{ "status": "Published" }
```

### Why this is a logic flaw

* Authorization exists
* Input is valid
* Flow rules violated

### Reviewer mental trigger

🧠

> “Can steps be skipped?”

---

## Pattern 6: Role Confusion in Business Rules

### Rule

> Managers approve, Admins manage users.

### Code

```csharp
if (User.IsInRole("Admin"))
{
    ApproveRequest();
}
```

### Why this is wrong

* Role != responsibility
* Admin is *not* a manager

### Why scanners miss it

* Auth check exists
* Looks intentional

### Reviewer mental trigger

🧠

> “Does role actually match this action?”

---

## Pattern 7: Cross-Tenant Data Mixing (Enterprise Killer)

### Code

```csharp
var report = _repo.GetReport(reportId);
```

### What’s missing

❌ Tenant / hospital check

### Result

* Data leakage across hospitals

### Reviewer mental trigger

🧠

> “Where is tenant isolation enforced?”

---

## Pattern 8: Discount / Promotion Abuse (CTF-Friendly)

### Code

```csharp
if (!user.HasUsedPromo)
{
    ApplyPromo();
}
```

### What attacker does

* Uses multiple requests
* Or resets state elsewhere

### Why this matters

* Financial loss
* Hard to detect

### Reviewer mental trigger

🧠

> “Can this be replayed?”

---

## 🧠 One Rule That Finds Business Logic Bugs

Ask these **three questions**:

1. ❓ What is the real-world rule?
2. ❓ Where is it enforced in code?
3. ❓ What happens if I repeat or reorder actions?

If the answer to #2 is:

* “UI”
* “Assumed earlier”
* “Another service probably handles it”

→ vulnerability likely exists.

---

## Why This Is the HARDEST Category

* No signatures
* No dangerous APIs
* Requires domain understanding
* Requires reading *flows*, not files

This is why **humans beat scanners** here.

# 🔐 Attack #8: Cryptographic Misuse in ASP.NET Core

This is not about *breaking crypto*.
It’s about **using crypto incorrectly**.

Most devs don’t *implement* crypto —
they **misuse APIs they don’t fully understand**.

---

## 🧠 Mental Model (Read This First)

Crypto fails when developers:

* invent their own schemes
* use crypto for the wrong purpose
* skip one required step
* reuse secrets incorrectly

The app *looks secure*, but the guarantee is gone.

---

## Pattern 1: Hashing Instead of Password Hashing (EASY)

### Developer intention

> “Hash passwords before storing.”

### Code

```csharp
var hash = SHA256.HashData(Encoding.UTF8.GetBytes(password));
```

### Why this is wrong

* Fast hash
* No salt
* Easy to brute-force

### Why this happens

* Dev knows “hashing is good”
* Doesn’t know about password-specific hashing

### Reviewer mental trigger

🧠

> “Is this a password hash or a general hash?”

---

## Pattern 2: Hardcoded Secrets (Very Common)

### Code

```csharp
private const string JwtKey = "SuperSecretKey123!";
```

### Why this is dangerous

* Key leaks via repo
* Same key everywhere
* Cannot rotate safely

### Why scanners sometimes miss

* Looks like config
* Not obviously crypto misuse

### Reviewer mental trigger

🧠

> “Where does this secret live in prod?”

---

## Pattern 3: Static IV in Encryption (Subtle)

### Code

```csharp
var iv = new byte[16];
var encryptor = aes.CreateEncryptor(key, iv);
```

### Why this breaks security

* Same plaintext → same ciphertext
* Patterns leak
* Enables replay and analysis

### Reviewer mental trigger

🧠

> “Is randomness used per encryption?”

---

## Pattern 4: Using Encryption Instead of Signing (Classic JWT Bug)

### Developer intention

> “Protect token data.”

### Code

```csharp
var encrypted = Encrypt(payload);
```

### What’s missing

❌ Integrity
❌ Authenticity

### Result

Attacker modifies ciphertext → app decrypts blindly

### Reviewer mental trigger

🧠

> “How do we know this wasn’t modified?”

---

## Pattern 5: JWT Without Validation (Very Dangerous)

### Code

```csharp
var token = handler.ReadJwtToken(jwt);
```

### What’s missing

* Signature validation
* Issuer
* Audience
* Expiry

### Result

Any token works.

### Reviewer mental trigger

🧠

> “Where is validation actually done?”

---

## Pattern 6: Data Protection API Misuse (ASP.NET Core–Specific)

### Code

```csharp
var protector = provider.CreateProtector("purpose");
var data = protector.Protect(input);
```

Later:

```csharp
var protector = provider.CreateProtector("different-purpose");
protector.Unprotect(data);
```

### Why this is broken

* Purpose mismatch
* Unexpected behavior
* Dev disables checks to “fix” it

### Reviewer mental trigger

🧠

> “Is purpose consistent and meaningful?”

---

## Pattern 7: Rolling Your Own Crypto (Always Bad)

### Code

```csharp
var encrypted = Convert.ToBase64String(
    Xor(data, key)
);
```

### Why this is broken

* Obfuscation ≠ encryption
* Predictable
* Reversible

### Reviewer mental trigger

🧠

> “Why not use a standard library?”

---

## Pattern 8: Token Reuse Across Contexts (Enterprise Bug)

### Scenario

* Same token used for:

  * auth
  * password reset
  * API access

### Why this is dangerous

* One leak breaks everything
* Scope confusion

### Reviewer mental trigger

🧠

> “What is this token *for*?”

---

## 🧠 One Rule That Catches Crypto Bugs

Ask ONE question:

> ❓ What security guarantee is this crypto supposed to give?

If you can’t answer:

* confidentiality?
* integrity?
* authenticity?
* freshness?

→ the crypto is probably wrong.

---

## Why Crypto Misuse Is Perfect for CTFs

* Easy version: SHA256 passwords
* Hard version: correct API, wrong usage
* Scanners catch some, miss many
* Teaches *thinking*, not algorithms

---

## 🏁 You Now Have the Full Set

We covered:

1. SQL Injection
2. Authentication Bypass
3. IDOR / Access Control
4. Insecure Deserialization
5. File Upload → RCE
6. SSRF
7. Business Logic Flaws
8. Cryptographic Misuse





