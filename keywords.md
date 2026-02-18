
# 🔴 1️⃣ SQL Injection & Database Access

### Core SQL patterns

```
SELECT
UPDATE
DELETE
INSERT
ExecuteReader
ExecuteNonQuery
ExecuteScalar
CommandText
SqlCommand
OracleCommand
```

### Dangerous patterns

```
string.Format(
+ Request.
+ txt
$"
AddWithValue
Parameters.Add(
EXECUTE IMMEDIATE
```

### Stored procedure risks

```
CommandType.StoredProcedure
ExecuteImmediate
```

---

# 🔴 2️⃣ Authentication & Password Handling

```
FormsAuthentication
FormsAuthenticationTicket
Membership
ValidateUser
SignIn
Authenticate
Login
```

### Weak crypto

```
MD5
SHA1
GetHashCode
DES
TripleDES
```

### Password handling

```
password =
pwd =
HashPassword
EncryptPassword
```

---

# 🔴 3️⃣ Authorization & Access Control

```
[Authorize]
AllowAnonymous
User.IsInRole
IsInRole(
PrincipalPermission
role ==
Request.QueryString["id"]
Request.Form["id"]
```

Look especially for:

```
id
userId
accountId
customerId
```

(These often lead to IDOR.)

---

# 🔴 4️⃣ Insecure Deserialization (VERY IMPORTANT in .NET 4)

```
BinaryFormatter
LosFormatter
ObjectStateFormatter
JavaScriptSerializer
DataContractSerializer
NetDataContractSerializer
Deserialize(
```

These are high-risk in legacy apps.

---

# 🔴 5️⃣ ViewState & MachineKey

```
enableViewStateMac
viewStateEncryptionMode
machineKey
ViewStateUserKey
```

Also search:

```
__VIEWSTATE
```

---

# 🔴 6️⃣ File Upload & File Access

```
HttpPostedFile
FileUpload
Request.Files
SaveAs(
Server.MapPath(
File.Read
File.Write
Path.Combine
```

---

# 🔴 7️⃣ XSS & Output Encoding

```
Html.Raw
Response.Write
InnerHtml
Literal
validateRequest="false"
Request.Unvalidated
```

---

# 🔴 8️⃣ Session & Cookie Security

```
Session[
SessionID
FormsAuthentication.SetAuthCookie
httpOnlyCookies
requireSSL
cookieless
```

---

# 🔴 9️⃣ Configuration & Debug Exposure

```
debug="true"
customErrors mode="Off"
compilation debug
trace enabled
```

---

# 🔴 🔟 Logging & Information Disclosure

```
ex.ToString
StackTrace
Trace.Write
log.
Logger
Console.WriteLine
```

---

# 🔴 11️⃣ Cryptography Misuse

```
Rijndael
AES
CreateEncryptor
CreateDecryptor
key =
IV =
ECB
```

---

# 🔴 12️⃣ Dangerous System Calls

```
Process.Start
cmd.exe
powershell
System.Diagnostics.Process
```

---

# 🔴 13️⃣ Request Handling & Input Sources

These are important for tracing data flow.

```
Request.QueryString
Request.Form
Request.Params
Request.Headers
Request.Cookies
```

---

# 🔴 14️⃣ CORS & Web API (If Used)

```
ApiController
EnableCors
AllowAnyOrigin
HttpGet
HttpPost
Route(
```

---

# 🔥 If You Want a Short "Top 25 Must-Search First" List

If you're short on time, search these first:

```
BinaryFormatter
LosFormatter
machineKey
enableViewStateMac
Html.Raw
validateRequest="false"
MD5
SHA1
Process.Start
SaveAs(
Server.MapPath
Request.QueryString
User.IsInRole
FormsAuthenticationTicket
ExecuteImmediate
OracleCommand
CommandText =
debug="true"
customErrors mode="Off"
AddWithValue
```

These alone catch most critical issues in legacy .NET 4 apps.

# 🔥 1️⃣ Broken Access Control (Most Common in Healthcare)

Healthcare systems usually have roles like:

* Admin
* Doctor
* Nurse
* Lab Technician
* Billing
* Patient

### 🚨 Real Vulnerability Pattern: IDOR in Patient Records

```csharp
int patientId = Convert.ToInt32(Request.QueryString["id"]);
var patient = db.Patients.Find(patientId);
```

If ownership or role validation is missing:

```
?patientId=102 → ?patientId=103
```

➡ Doctor A can access Doctor B’s patients
➡ Nurse accesses billing data
➡ Patient accesses another patient’s report

**Impact:** Massive PHI breach (HIPAA violation level)

---

# 🔥 2️⃣ Horizontal Privilege Escalation in Lab/Prescription Modules

Common pattern:

```csharp
if(User.IsInRole("Doctor"))
{
    ApprovePrescription();
}
```

But backend does NOT verify:

* Is this doctor assigned to this patient?

➡ Any doctor can approve any prescription.

Very common in:

* Lab approval
* Diagnosis finalization
* Insurance approval

---

# 🔥 3️⃣ ViewState Exploitation (Legacy .NET 4 Apps)

Healthcare systems often run older ASP.NET 4 builds.

If:

```xml
enableViewStateMac="false"
```

Or weak/reused `<machineKey>`

➡ Attackers can tamper ViewState
➡ Possible remote code execution
➡ Or business logic manipulation

---

# 🔥 4️⃣ Mass Assignment (Overposting) in Patient Models

Classic MVC 4 pattern:

```csharp
public ActionResult Update(Patient model)
{
    db.Entry(model).State = EntityState.Modified;
}
```

If `Patient` model contains:

```
IsCritical
InsuranceApproved
IsVIP
BillingStatus
```

Attacker can modify hidden properties via crafted request.

---

# 🔥 5️⃣ PHI Stored in Plaintext

Very common:

* Aadhaar
* SSN
* Insurance number
* Medical history
* Diagnosis notes

Check:

* Are these encrypted in DB?
* Or stored raw?

Many enterprise healthcare apps store everything plaintext in Oracle.

---

# 🔥 6️⃣ File Upload → Medical Reports (High Risk)

Modules:

* Upload lab report
* Upload prescription
* Upload scan

Common issue:

```csharp
file.SaveAs(Server.MapPath("~/Reports/" + file.FileName));
```

If no validation:

* Upload `.aspx` file
* RCE possible

Or:

* Path traversal to read `web.config`

---

# 🔥 7️⃣ Hardcoded Database Credentials

In healthcare apps, I often find:

```xml
connectionString="User Id=app;Password=app123;"
```

If source leaked → full DB compromise.

---

# 🔥 8️⃣ Insecure Deserialization

Legacy modules using:

```
BinaryFormatter
JavaScriptSerializer
```

If used on:

* Hidden fields
* Cookies
* Request body

➡ Remote Code Execution risk.

---

# 🔥 9️⃣ Excessive Oracle Privileges

Very common mistake:

Application DB user has:

* CREATE ANY TABLE
* DROP ANY TABLE
* DBA

If SQL injection exists → full DB takeover.

---

# 🔥 🔟 Business Logic Flaws in Billing

Healthcare apps almost always have:

* Billing adjustments
* Insurance claim amounts
* Manual override fields

Common flaw:

```csharp
decimal amount = Convert.ToDecimal(Request.Form["amount"]);
```

If server trusts client-provided billing amount:
➡ Patient reduces bill
➡ Staff manipulates charges

---

# 🔥 11️⃣ Logging Sensitive Data

Common:

```csharp
_logger.Log("Patient details: " + JsonConvert.SerializeObject(patient));
```

Logs may contain:

* Diagnosis
* Contact details
* Insurance numbers

If log server compromised → full PHI dump.

---

# 🔥 12️⃣ Session Fixation / Shared Workstations

Hospitals often use shared terminals.

If:

* Session not regenerated after login
* Long timeout
* No auto logout

➡ Nurse logs out
➡ Next person accesses previous session

---

# 🔥 13️⃣ PDF / Report Generation Injection

Healthcare apps generate:

* Discharge summary
* Lab reports
* Billing statements

If data inserted into HTML → PDF without encoding:
➡ Stored XSS
➡ JavaScript execution in internal portals

---

# 🔥 14️⃣ Missing Audit Trails

Regulatory requirement:

* Who viewed patient?
* Who modified diagnosis?
* Who downloaded report?

Many apps lack:

* Proper audit logging
* Immutable logs

---

# 🔥 15️⃣ Weak Password Policies for Internal Users

Very common:

* No MFA
* No lockout
* 6 character passwords
* Shared accounts like:

  * nurse1
  * admin
  * billing

---

# ⚠ Why Healthcare Apps Are High Risk

Impact is not just technical:

* Legal penalties
* Regulatory violations
* Reputation damage
* Patient safety risk

In healthcare, **Broken Access Control > SQL Injection** in practical impact.

---

# 🎯 If I Were Reviewing This App

My priority order would be:

1. Patient record access control
2. Role validation logic
3. File upload modules
4. Billing manipulation logic
5. Deserialization usage
6. DB privilege level
7. Encryption of PHI
8. Logging of sensitive data

