using HealthCorp.Core.Entities;
using HealthCorp.Infrastructure.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace HealthCorp.Web.Controllers;

[Authorize]
public class MedicalRecordsController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly IWebHostEnvironment _environment;

    public MedicalRecordsController(ApplicationDbContext context, IWebHostEnvironment environment)
    {
        _context = context;
        _environment = environment;
    }

    // GET: MedicalRecords
    public async Task<IActionResult> Index()
    {
        var records = _context.MedicalRecords.Include(m => m.Patient);
        return View(await records.ToListAsync());
    }

    // GET: MedicalRecords/Upload
    public IActionResult Upload()
    {
        ViewData["PatientId"] = new SelectList(_context.Patients, "Id", "LastName");
        return View();
    }

    // POST: MedicalRecords/Upload
    // VULNERABILITY: File Upload (Easy: Extension check only, Hard: Path Traversal in filename)
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Upload(MedicalRecord record, IFormFile? fileUpload)
    {
        if (fileUpload != null && fileUpload.Length > 0)
        {
            // Easy Check: Extension
            var ext = Path.GetExtension(fileUpload.FileName).ToLower();
            if (ext != ".pdf" && ext != ".jpg" && ext != ".png")
            {
                ModelState.AddModelError("", "Only PDF, JPG, and PNG allowed.");
                ViewData["PatientId"] = new SelectList(_context.Patients, "Id", "LastName", record.PatientId);
                return View(record);
            }

            // VULNERABILITY: Path Traversal
            // Trusting fileUpload.FileName blindly. 
            // If FileName is "../../system32/cmd.exe", this might try to write there.
            var fileName = fileUpload.FileName; 
            var uploadPath = Path.Combine(_environment.WebRootPath, "uploads");
            
            if (!Directory.Exists(uploadPath)) Directory.CreateDirectory(uploadPath);

            var filePath = Path.Combine(uploadPath, fileName);
            
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await fileUpload.CopyToAsync(stream);
            }

            record.FilePath = "/uploads/" + fileName;
            record.ContentType = fileUpload.ContentType;
            record.CreatedByUserId = 1; // Simplification
            record.CreatedAt = DateTime.Now;

            _context.Add(record);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        ViewData["PatientId"] = new SelectList(_context.Patients, "Id", "LastName", record.PatientId);
        return View(record);
    }

    // GET: MedicalRecords/PreviewImage?url=...
    // VULNERABILITY: SSRF (Easy)
    [HttpGet]
    public async Task<IActionResult> PreviewImage(string url)
    {
        if (string.IsNullOrEmpty(url)) return BadRequest("URL required");

        // VULNERABILITY: No validation of URL scheme or destination.
        // Attacker can pass "http://localhost:80/admin" or "file:///etc/passwd" (if allowed by HttpClient)
        // HttpClient doesn't support file:// by default usually, but http://internal-service is possible.
        
        using var client = new HttpClient();
        var bytes = await client.GetByteArrayAsync(url);
        
        return File(bytes, "image/jpeg");
    }
}
