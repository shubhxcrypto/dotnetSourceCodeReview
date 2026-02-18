
# 🔴 1. Injection Vulnerabilities (Top Priority)

## ✅ SQL Injection (Oracle)

**Search for:**

* `string + userInput`
* `$"{var}"`
* `.Format(`
* `"WHERE " +`
* `"SELECT " +`
* `ExecuteReader()`
* `ExecuteNonQuery()`

### ❌ Dangerous Pattern

```csharp
string query = "SELECT * FROM USERS WHERE USERNAME = '" + username + "'";
```

### ✅ Secure Pattern

```csharp
cmd.Parameters.Add(":username", OracleDbType.Varchar2).Value = username;
```

### 🔎 Check:

* Are **all DB queries parameterized?**
* Is **OracleParameter** used everywhere?
* Any dynamic `IN (...)` queries?
* Any dynamic `ORDER BY` built from user input?

---

## ✅ Command Injection

Search for:

* `Process.Start()`
* `cmd.exe`
* `powershell`
* `Runtime.getRuntime`
* `System.Diagnostics.Process`

Check if user input flows into these.

---

## ✅ LDAP Injection (If LDAP used)

Search:

* `DirectoryEntry`
* `DirectorySearcher`

Ensure filters are escaped properly.

---

# 🟠 2. Authentication & Authorization

## ✅ Authentication Checks

* Is custom auth used?
* Are passwords:

  * Hashed?
  * Salted?
  * Using strong algorithms? (PBKDF2 / bcrypt / Argon2)
* ❌ No MD5 / SHA1

Search:

```
MD5
SHA1
FormsAuthentication
Membership
```

---

## ✅ Authorization Checks

* Is `[Authorize]` used properly?
* Any missing role checks?
* Any IDOR pattern?

### IDOR Example

```csharp
var user = db.Users.Find(userId);
```

If `userId` comes from query string — check if ownership validated.

---

# 🟡 3. Session & Cookie Security

Check in `web.config`:

```xml
<authentication mode="Forms">
```

### Verify:

* `requireSSL="true"`
* `httpOnlyCookies="true"`
* `cookieless="UseCookies"`
* `timeout` reasonable?

---

## Check for:

* Session fixation
* Session ID regeneration on login
* Insecure ViewState

### ViewState Check

In `web.config`:

```xml
<pages enableViewStateMac="true" viewStateEncryptionMode="Always" />
```

If `enableViewStateMac="false"` → 🚨 Critical

---

# 🟡 4. CSRF Protection

Check:

* Is `@Html.AntiForgeryToken()` used?
* Are POST methods protected?
* Is `[ValidateAntiForgeryToken]` used?

Search:

```
HttpPost
[ValidateAntiForgeryToken]
```

---

# 🟡 5. XSS (Cross Site Scripting)

## Check:

* Any `@Html.Raw()`
* Response.Write(userInput)
* JavaScript injection in Razor
* Stored DB content rendered without encoding

### Dangerous:

```csharp
@Html.Raw(Model.Comment)
```

### Safe:

```csharp
@Model.Comment
```

---

# 🔵 6. Oracle-Specific Security Checks

## ✅ Hardcoded Credentials

Search:

```
Data Source=
User Id=
Password=
```

Check:

* Is connection string encrypted?
* Is `web.config` protected with `aspnet_regiis`?

---

## ✅ Excessive Privileges

Ask:

* Does DB user have `DBA`?
* Does app use separate read/write users?

---

## ✅ PL/SQL Injection

Check:

* Any `EXECUTE IMMEDIATE`
* Stored procedures taking raw strings
* Dynamic SQL inside PL/SQL

---

# 🟡 7. File Handling

Search:

```
File.Write
File.Read
Server.MapPath
FileUpload
```

Check:

* Path traversal
* File type validation
* File size validation
* Storage outside webroot?

---

# 🟡 8. Error Handling

Check:

* Is `customErrors mode="Off"` in production?
* Stack traces exposed?
* Oracle errors exposed?

---

# 🟢 9. Configuration Security (web.config)

### Must Check:

```xml
<customErrors mode="On" />
<compilation debug="false" />
<trust level="Full" />
```

⚠ If `debug="true"` → Information disclosure

---

# 🟢 10. Sensitive Data Exposure

Check:

* Logging of passwords?
* Logging of connection strings?
* Logs stored in public folder?

Search:

```
log.
Exception
Trace
```

---

# 🟢 11. Business Logic Vulnerabilities

These are MOST IMPORTANT in enterprise apps.

Check for:

* Price manipulation
* Role bypass
* Workflow bypass
* Parameter tampering
* Approval bypass

Example:

```csharp
if(role == "Admin")
```

Where does `role` come from?

---

# 🟢 12. Third Party Libraries

Check:

* Old Oracle client?
* Old Newtonsoft?
* Known vulnerable packages?

---

# 🟢 13. API Security (If Web API used)

Search:

```
ApiController
Route
HttpGet
HttpPost
```

Check:

* Missing auth?
* CORS misconfiguration?
* JSON deserialization issues?

---

# 🟢 14. Cryptography

Search:

```
Encrypt
Decrypt
Rijndael
AES
DES
```

Check:

* Hardcoded keys?
* ECB mode?
* Custom crypto implementation?

---

# 🟢 15. Logging & Monitoring

* Failed login logging?
* Audit trail?
* Sensitive data masked?

---

# 🔥 Practical Workflow (How You Should Review)

1. Start with `web.config`
2. Review authentication flow
3. Review authorization model
4. Review DB access layer
5. Review controllers
6. Review file upload logic
7. Review error handling
8. Review crypto usage
9. Review business logic
10. Review infrastructure configs

---

# 🧠 Since You Do Security & Bug Bounty

Extra checks for ASP.NET 4:

* Insecure ViewState deserialization
* MachineKey reuse
* Insecure deserialization
* BinaryFormatter usage
* JavaScriptSerializer issues

Search:

```
BinaryFormatter
LosFormatter
ObjectStateFormatter
JavaScriptSerializer
```



# 🔴 1. Injection Vulnerabilities (SQL Injection – Oracle Focus)

This is your **#1 priority**.

## 🎯 What You’re Looking For

Any place where **user input reaches a SQL query without proper parameterization**.

### 🔎 Search Patterns

Search in code:

```
"SELECT "
"UPDATE "
"DELETE "
"INSERT "
+ userInput
string.Format(
$"
ExecuteReader(
ExecuteNonQuery(
```

---

## ❌ Vulnerable Example

```csharp
string query = "SELECT * FROM USERS WHERE USERNAME = '" + txtUsername.Text + "'";
```

If attacker enters:

```
' OR '1'='1
```

Oracle executes:

```
SELECT * FROM USERS WHERE USERNAME = '' OR '1'='1'
```

➡ Full data exposure.

---

## ✅ Secure Example

```csharp
OracleCommand cmd = new OracleCommand("SELECT * FROM USERS WHERE USERNAME = :username", conn);
cmd.Parameters.Add(":username", OracleDbType.Varchar2).Value = txtUsername.Text;
```

---

## 🚨 Special Oracle Checks

* Dynamic `IN (...)` clauses
* Dynamic `ORDER BY`
* Stored procedures using `EXECUTE IMMEDIATE`
* PL/SQL dynamic queries

---

# 🟠 2. Authentication Security

Now check how users log in.

## 🎯 Things to Verify

### 1️⃣ Password Storage

Search:

```
MD5
SHA1
GetHashCode
```

❌ Bad:

```csharp
MD5.Create()
```

✅ Good:

* PBKDF2
* bcrypt
* Argon2

---

### 2️⃣ Login Logic

Check:

* Account lockout?
* Brute-force protection?
* CAPTCHA?
* MFA?

---

### 3️⃣ Hardcoded Credentials

Search:

```
username =
password =
connectionString
```

Check if DB password is visible in `web.config`.

---

# 🟠 3. Authorization (Access Control)

This is where many enterprise apps fail.

## 🎯 You Must Check:

Is the user allowed to access this data?

---

### 🔎 IDOR (Insecure Direct Object Reference)

Example:

```csharp
int userId = Convert.ToInt32(Request.QueryString["id"]);
var user = db.Users.Find(userId);
```

If attacker changes:

```
?id=5 → ?id=6
```

Do they get another user’s data?

Check:

* Is ownership validated?
* Are role checks done?

---

### 🔎 Role Checks

Search:

```
[Authorize]
User.IsInRole
if(role ==
```

Check:

* Is authorization done at controller level?
* Or only UI hiding buttons?

⚠ UI restriction ≠ Security

---

# 🟡 4. Session & Cookie Security

Check in `web.config`.

---

## 🎯 Important Settings

```xml
<authentication mode="Forms">
<httpCookies httpOnlyCookies="true" requireSSL="true" />
```

### Verify:

| Setting    | Why Important           |
| ---------- | ----------------------- |
| httpOnly   | Prevent JS cookie theft |
| requireSSL | Prevent HTTP hijacking  |
| timeout    | Session expiry          |
| cookieless | Should use cookies only |

---

## 🚨 ViewState Security (ASP.NET 4 specific)

Check:

```xml
<pages enableViewStateMac="true" />
```

If `false` → Critical vulnerability
Can lead to **remote code execution** in some cases.

Also check:

```
<machineKey>
```

If hardcoded & reused → dangerous.

---

# 🟡 5. CSRF (Cross-Site Request Forgery)

CSRF is very common in ASP.NET apps.

---

## 🎯 What to Check

For every POST method:

```csharp
[HttpPost]
public ActionResult UpdateProfile(...)
```

Check if it includes:

```csharp
[ValidateAntiForgeryToken]
```

And in view:

```csharp
@Html.AntiForgeryToken()
```

---

## ❌ If Missing

Attacker can create malicious site:

```html
<form action="https://target.com/updateRole" method="POST">
<input type="hidden" name="role" value="Admin">
</form>
```

If victim logged in → request executes.

---

# 🧠 Quick Priority Order (In Real Review)

1. SQL Injection
2. Authorization flaws
3. Authentication flaws
4. CSRF
5. Session misconfigurations


---

# 🔵 6. File Upload & File Handling Security

File upload is a **high-risk attack surface** in .NET Framework apps.

---

## 🎯 What to Check

Search:

```
FileUpload
HttpPostedFile
Request.Files
SaveAs(
Server.MapPath(
File.WriteAllText
File.ReadAllText
```

---

## 🚨 1️⃣ Unrestricted File Upload

Check:

* Is file extension validated?
* Is MIME type validated?
* Is content inspected?
* Is file size restricted?

### ❌ Dangerous

```csharp
file.SaveAs(Server.MapPath("~/uploads/" + file.FileName));
```

Attacker uploads:

```
shell.aspx
```

➡ Remote code execution possible.

---

## ✅ Secure Approach

* Whitelist extensions (.jpg, .pdf only)
* Rename file (GUID)
* Store outside webroot
* Scan file if possible

---

## 🚨 2️⃣ Path Traversal

If user input goes into file path:

```csharp
File.ReadAllText(Server.MapPath("~/docs/" + filename));
```

Attacker sends:

```
../../web.config
```

➡ Sensitive file disclosure.

---

# 🟡 7. Error Handling & Information Disclosure

Information leakage is very common.

---

## 🎯 Check `web.config`

```xml
<customErrors mode="On" />
<compilation debug="false" />
```

If:

```
debug="true"
```

➡ Full stack traces exposed.

---

## 🚨 Look For:

* Oracle error messages returned to UI
* Stack traces displayed
* Connection string exposed in exception

Search:

```
ex.ToString()
Response.Write(ex)
```

---

## ❌ Bad Example

```csharp
catch(Exception ex)
{
    return Content(ex.ToString());
}
```

---

# 🟢 8. Sensitive Data Exposure

Now check how sensitive data is handled.

---

## 🎯 Look For:

Search:

```
log
Trace
Console.WriteLine
Exception
```

---

## 🚨 Things to Verify

* Are passwords logged?
* Is connection string logged?
* Is PAN/Aadhaar stored in plaintext?
* Is encryption used properly?

---

## 🔐 Encryption Checks

Search:

```
AES
DES
Rijndael
TripleDES
```

Check:

* Hardcoded encryption keys?
* ECB mode used?
* Custom crypto implementation?

---

### ❌ Dangerous

```csharp
string key = "mysecretkey123";
```

Hardcoded keys = bad practice.

---

# 🟢 9. Insecure Deserialization (ASP.NET 4 Important)

This is VERY dangerous in .NET Framework apps.

---

## 🎯 Search For:

```
BinaryFormatter
LosFormatter
ObjectStateFormatter
JavaScriptSerializer
DataContractSerializer
```

---

## 🚨 Why Dangerous?

If user-controlled data is deserialized:

```csharp
BinaryFormatter bf = new BinaryFormatter();
bf.Deserialize(stream);
```

➡ Remote Code Execution possible.

---

## 🔎 Check:

* Is deserialization done on:

  * Cookies?
  * ViewState?
  * Hidden fields?
  * Request body?

---

# 🟢 10. Configuration & Infrastructure Security

Now check overall configuration security.

---

## 🎯 `web.config` Deep Review

Check for:

### 1️⃣ MachineKey

```xml
<machineKey validationKey=...
```

* Is it hardcoded?
* Is it reused across environments?

---

### 2️⃣ Request Validation

```xml
validateRequest="false"
```

If false → XSS risk.

---

### 3️⃣ CORS Misconfiguration (if Web API used)

Search:

```
EnableCors
AllowAnyOrigin
```

Danger:

```
AllowAnyOrigin()
```

---

### 4️⃣ HTTP Security Headers

Check if implemented:

* X-Frame-Options
* X-Content-Type-Options
* Content-Security-Policy
* Strict-Transport-Security

---

# 🎯 Real-World Priority Order (Enterprise Apps)

1. File Upload flaws
2. IDOR & access control
3. Deserialization issues
4. Information leakage
5. Config misconfiguration


Perfect 😎
Now we go into **real reviewer mode** — this is the stuff that actually speeds up enterprise code review.

I’ll break it into 3 sections:

1. 🔎 Exact grep / regex patterns
2. 🧠 Advanced ASP.NET Framework 4 exploitation patterns
3. 🛡 Oracle DB misconfiguration checklist

---

# 🔎 1️⃣ Exact Grep / Regex Patterns for Fast Code Review

Use these in:

* Visual Studio "Find in Files"
* grep
* ripgrep
* SourceGraph
* GitHub search

---

## 🔴 SQL Injection Patterns

### 🔎 Find string concatenation inside SQL

```
"SELECT.*\+
"UPDATE.*\+
"DELETE.*\+
"INSERT.*\+
```

```
\+\s*Request\.
\+\s*txt
\+\s*user
string\.Format\(.*SELECT
\$".*SELECT
```

---

## 🔴 Oracle-Specific Risk Patterns

```
EXECUTE IMMEDIATE
OracleCommand\(
CommandText\s*=
AddWithValue
Parameters\.Add\(
```

Check if parameters are actually bound.

---

## 🔴 Hardcoded Credentials

```
User Id=
Password=
Data Source=
pwd=
uid=
```

```
password\s*=
connectionString
```

---

## 🔴 Insecure Deserialization

```
BinaryFormatter
LosFormatter
ObjectStateFormatter
JavaScriptSerializer
Deserialize\(
```

---

## 🔴 File Upload & Path Traversal

```
SaveAs\(
Server\.MapPath
Request\.Files
File\.Read
File\.Write
Path\.Combine
```

---

## 🔴 XSS Risk Patterns

```
Html\.Raw
Response\.Write
InnerHtml
Literal
validateRequest="false"
```

---

## 🔴 Authorization Flaws

```
Request\.QueryString
Request\.Form
id\]
userId
accountId
IsInRole
\[Authorize
```

Look for object access without ownership validation.

---

## 🔴 Crypto Weakness

```
MD5
SHA1
DES
TripleDES
ECB
key =
IV =
```

---

## 🔴 Debug & Error Disclosure

```
debug="true"
customErrors mode="Off"
ex\.ToString
StackTrace
```

---

# 🧠 2️⃣ Advanced ASP.NET Framework 4 Exploitation Patterns

These are real-world attack patterns seen in legacy enterprise apps.

---

## 🔥 1️⃣ ViewState Exploitation (Very Important)

If:

```
enableViewStateMac="false"
```

Or weak/static machineKey

➡ Possible:

* ViewState tampering
* RCE via ysoserial.net gadget chains

Search:

```
enableViewStateMac
machineKey
```

---

## 🔥 2️⃣ Insecure Deserialization via ViewState

ASP.NET 4 had historical issues where:

* ViewState MAC disabled
* machineKey predictable

This can lead to:

* Remote code execution

---

## 🔥 3️⃣ Role Bypass via Hidden Fields

Check forms like:

```html
<input type="hidden" name="role" value="Admin" />
```

If backend trusts it:

```csharp
if(role == "Admin")
```

➡ Privilege escalation.

---

## 🔥 4️⃣ Mass Assignment (Overposting)

Common in MVC 4:

```csharp
public ActionResult Update(User model)
{
    db.Entry(model).State = EntityState.Modified;
}
```

If model contains:

```
IsAdmin
IsApproved
Balance
```

Attacker can modify sensitive fields.

Fix:

```
[Bind(Include="AllowedField1,AllowedField2")]
```

---

## 🔥 5️⃣ MachineKey Reuse Across Environments

If same machineKey used:

* Cookie tampering possible
* Cross-app token replay
* Auth ticket forging

Search:

```
<machineKey
```

---

## 🔥 6️⃣ Insecure FormsAuthentication Ticket

Search:

```
FormsAuthenticationTicket
Encrypt(
Decrypt(
```

Check:

* Custom ticket creation?
* Sensitive data inside ticket?

---

## 🔥 7️⃣ Custom Crypto

If developer implemented:

```
EncryptString()
DecryptString()
```

Check for:

* Hardcoded key
* ECB mode
* No IV
* No salt

---

## 🔥 8️⃣ Request Validation Disabled

```
validateRequest="false"
```

Then check:

* Is output encoding enforced?
* Is HTML sanitized?

---

# 🛡 3️⃣ Oracle DB Misconfiguration Checklist

Now let’s move to database layer.

---

## 🔴 1️⃣ Excessive Privileges

Ask DBA or check connection user:

Does app user have:

* DBA
* CREATE USER
* DROP ANY TABLE
* EXECUTE ANY PROCEDURE

App should have minimal rights:

* SELECT
* INSERT
* UPDATE
* DELETE only on required tables

---

## 🔴 2️⃣ Dynamic PL/SQL

Search in stored procedures:

```
EXECUTE IMMEDIATE
|| variable ||
```

Example:

```sql
v_sql := 'SELECT * FROM USERS WHERE ID = ' || user_input;
EXECUTE IMMEDIATE v_sql;
```

➡ SQL Injection inside stored procedure.

---

## 🔴 3️⃣ Hardcoded DB Credentials in Code

Check:

* appsettings
* web.config
* source files

Connection string should:

* Not be plaintext in repo
* Be encrypted using aspnet_regiis

---

## 🔴 4️⃣ No Encryption in Transit

Check:

* Is Oracle using TCPS?
* Or plain TCP?

---

## 🔴 5️⃣ No Row-Level Security

If multi-tenant system:

* Is data filtered by user ID?
* Or app trusts client?

---

## 🔴 6️⃣ Error Message Disclosure

If Oracle errors shown:

* ORA-00933
* ORA-01756

Then attacker can tune injection payload.

---

## 🔴 7️⃣ Default Accounts Enabled

Check if DB has:

* SCOTT
* HR
* SYSTEM

Enabled in production.

---

# 🔥 Real Enterprise Attack Path (How It Usually Happens)

1. SQL Injection in app
2. DB user has excessive privilege
3. Attacker dumps schema
4. Finds password reset tokens
5. Finds machineKey in config table
6. Forges auth ticket
7. Full compromise

This chain is very real in legacy .NET 4 apps.

---
