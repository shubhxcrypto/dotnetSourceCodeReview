using HealthCorp.Core.Entities;
using HealthCorp.Infrastructure.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace HealthCorp.Web.Controllers;

[Authorize]
public class AppointmentsController : Controller
{
    private readonly ApplicationDbContext _context;

    public AppointmentsController(ApplicationDbContext context)
    {
        _context = context;
    }

    // GET: Appointments
    public async Task<IActionResult> Index()
    {
        var applicationDbContext = _context.Appointments.Include(a => a.Doctor).Include(a => a.Patient);
        return View(await applicationDbContext.ToListAsync());
    }

    // GET: Appointments/Create
    public IActionResult Create()
    {
        ViewData["DoctorId"] = new SelectList(_context.Users.Where(u => u.Role == "Doctor"), "Id", "Username");
        ViewData["PatientId"] = new SelectList(_context.Patients, "Id", "LastName");
        return View();
    }

    // POST: Appointments/Create
    // VULNERABILITY: Race Condition / Double Booking
    // This logic checks for conflicts but is susceptible to race conditions because 
    // there is no lock or database constraint enforcing uniqueness on (DoctorId, Time).
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create([Bind("Id,PatientId,DoctorId,AppointmentTime,Reason,Notes")] Appointment appointment)
    {
        if (ModelState.IsValid)
        {
            // Business Logic Check: Is doctor available?
            var conflict = await _context.Appointments.AnyAsync(a => 
                a.DoctorId == appointment.DoctorId && 
                a.AppointmentTime == appointment.AppointmentTime);

            if (conflict)
            {
                ModelState.AddModelError("", "Doctor is already booked at this time."); // Vulnerability: Flaw allows bypassing this in high concurrency
            }
            else
            {
                // VULNERABILITY: Massive lag or separate transaction could allow race here
                
                appointment.Status = "Scheduled";
                _context.Add(appointment);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
        }
        ViewData["DoctorId"] = new SelectList(_context.Users.Where(u => u.Role == "Doctor"), "Id", "Username", appointment.DoctorId);
        ViewData["PatientId"] = new SelectList(_context.Patients, "Id", "LastName", appointment.PatientId);
        return View(appointment);
    }
}
