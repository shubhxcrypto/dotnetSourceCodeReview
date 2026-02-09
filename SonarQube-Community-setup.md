# SonarQube_For_DotNet


# **Guide: Setting up SonarQube and Scanning OWASP WebGoat .NET Project**

## **1. Downloading and Setting Up SonarQube**

1. Go to the official SonarQube website: [https://www.sonarqube.org/downloads/](https://www.sonarqube.org/downloads/).
2. Download **SonarQube Community Edition**.
3. Extract the downloaded zip to a folder (e.g., `C:\SonarQube`).
4. Start SonarQube:

   * Navigate to `C:\SonarQube\bin\windows-x86-64\`.
   * Run `StartSonar.bat`.
   * Wait for the server to start.
5. Open browser and access the dashboard: [http://localhost:9000](http://localhost:9000).
6. Log in with default credentials: `admin` / `admin`.
7. Generate a **user token** for analysis:

   * Go to `My Account → Security → Generate Tokens`.
   * Copy token for later use.

---

## **2. Downloading SonarScanner for .NET**

1. Go to the official page: [https://docs.sonarqube.org/latest/analysis/scan/sonarscanner-for-msbuild/](https://docs.sonarqube.org/latest/analysis/scan/sonarscanner-for-msbuild/)
2. Download **SonarScanner for MSBuild** (for .NET Framework projects) or use `dotnet tool install --global dotnet-sonarscanner` for .NET Core projects.
3. Add the scanner folder to your `PATH` (optional, but convenient).

---

## **3. Preparing the OWASP WebGoat .NET Project**

1. Download OWASP WebGoat .NET from GitHub: [https://github.com/WebGoat/WebGoat.NET](https://github.com/WebGoat/WebGoat.NET)
2. Open **Developer Command Prompt** or normal CMD.
3. Navigate to the project folder:

   ```cmd
   cd C:\Users\YourName\Desktop\codeReview\OWASP-WebGoat.NET
   ```

---

## **4. Running SonarScanner on the Project**

### **.NET Core Projects**

```cmd
dotnet sonarscanner begin /k:"webGoat" /d:sonar.host.url="http://localhost:9000" /d:sonar.token="YOUR_TOKEN"
dotnet build
dotnet sonarscanner end /d:sonar.token="YOUR_TOKEN"
```

### **.NET Framework Projects**

```cmd
SonarScanner.MSBuild.exe begin /k:"webGoat" /d:sonar.host.url="http://localhost:9000" /d:sonar.token="YOUR_TOKEN"
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" WebGoat.NET.sln /t:Rebuild
SonarScanner.MSBuild.exe end /d:sonar.token="YOUR_TOKEN"
```

---

## **5. Problems Faced and Solutions**

| Problem                                              | Cause                                                                   | Solution                                                                                                                            |
| ---------------------------------------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **MSBuild error: .NET Framework v3.5 not found**     | Project targets **.NET Framework 3.5** but it wasn’t installed          | Installed **.NET Framework 3.5 Developer Pack** from [https://aka.ms/msbuild/developerpacks](https://aka.ms/msbuild/developerpacks) |
| **Scanner end fails**                                | Build did not succeed                                                   | Fixed compilation errors first, then ran `SonarScanner.MSBuild.exe end`                                                             |
| **.NET Core command works but .NET Framework fails** | Different scanners: `dotnet sonarscanner` vs `SonarScanner.MSBuild.exe` | Used correct scanner for project type                                                                                               |
## **For .Net Framework make sure you have refrence assemblies installed else project build fails**
## **Installing .NET Framework 3.5 on Windows (When It’s Not Listed)**

Modern versions of Windows (Windows 10 / 11) **do not ship with .NET Framework 3.5 enabled by default**, and it **does not appear as a normal SDK download** like newer .NET versions.

However, **.NET Framework 3.5 is included inside Windows as an optional feature**.

### **Method 1: Enable .NET Framework 3.5 from Windows Features (Recommended)**

1. Open **Control Panel**
2. Go to **Programs → Programs and Features**
3. Click **Turn Windows features on or off**
4. Enable:

   ```
   ☑ .NET Framework 3.5 (includes .NET 2.0 and 3.0)
   ```
5. Click **OK**
6. Windows will download required files and install the framework
7. Restart if prompted

This installs the **runtime and reference assemblies** required by MSBuild.

---

### **Method 2: Install Using Command Line (Offline / Reliable)**

If Windows Features fails or shows errors, use **DISM**:

```cmd
DISM /Online /Enable-Feature /FeatureName:NetFx3 /All
```

If your machine has **no internet access**, mount a Windows ISO and run:

```cmd
DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /Source:X:\sources\sxs /LimitAccess
```

(Replace `X:` with the ISO drive letter.)

---

### **Method 3: Verify Installation**

After installation, verify by running:

```cmd
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5"
```

Or confirm via MSBuild by rebuilding the solution:

```cmd
msbuild WebGoat.NET.sln /t:Rebuild
```

If installed correctly, **MSB3644 / MSB3645 errors disappear**.

---

## **Important Clarification (Very Common Confusion)**

 Installing **“.NET Framework 3.5 Runtime” alone is NOT enough**
 MSBuild requires **reference assemblies**, which come from:

* Windows Feature **OR**
* .NET Framework **Developer Pack**

This is why Visual Studio + MSBuild failed even though “3.5 was installed”.

---

## **Why This Matters for SonarQube Scanning**

* SonarScanner for MSBuild **wraps the build**
* If MSBuild fails, **analysis cannot be uploaded**
* Installing .NET 3.5 correctly ensures:

  * Build success
  * Vulnerable code analysis
  * Accurate SonarQube results

---

## **Final Outcome**

After enabling **.NET Framework 3.5**:

* MSBuild completed successfully
* SonarScanner `begin → build → end` flow worked
* SonarQube displayed security vulnerabilities as expected

---

## **6. Notes / Observations**

* OWASP WebGoat is intentionally **vulnerable**; many warnings from SonarQube are expected (SQL injection, unsafe hashing, exception misuse).
* You must fix only **build-blocking errors** to run analysis; warnings can be left as-is.
* Always use the **correct scanner** for your project type.
* After analysis, results can be viewed on `http://localhost:9000` under your project key (`webGoat`).

## **toolsHelp**
### SonarQube gives commands but it works fine for .Net Core but create issue if we run same commands .net Framework so first make sure you have .NET Framework 3.5 Runtime

<img width="1278" height="694" alt="image" src="https://github.com/user-attachments/assets/7aa791e3-2e03-4f62-8f33-cc5415713cdf" />

## **Step 1**
<img width="1756" height="631" alt="image" src="https://github.com/user-attachments/assets/f10f735b-f738-422f-bb61-34a5bd5b010d" />

## **Step 2**
<img width="1776" height="625" alt="image" src="https://github.com/user-attachments/assets/fa086191-2fbc-48cc-846e-6bf852182a65" />

## **Step 3**
<img width="1779" height="779" alt="image" src="https://github.com/user-attachments/assets/6ede8ed8-7139-4263-bb25-d503298ec295" />

## **Final Output**
<img width="1920" height="828" alt="image" src="https://github.com/user-attachments/assets/fc4daa95-7804-4732-961d-974f037fa36c" />


