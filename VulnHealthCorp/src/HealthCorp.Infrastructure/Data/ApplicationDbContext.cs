using HealthCorp.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace HealthCorp.Infrastructure.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<User> Users { get; set; } = null!;
    public DbSet<Patient> Patients { get; set; } = null!;
    public DbSet<Appointment> Appointments { get; set; } = null!;
    public DbSet<MedicalRecord> MedicalRecords { get; set; } = null!;
    public DbSet<AuditLog> AuditLogs { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Oracle-specific conventions (optional but adds realism)
        // Usually Oracle objects are uppercase
        modelBuilder.Entity<User>().ToTable("USERS");
        modelBuilder.Entity<Patient>().ToTable("PATIENTS");
        modelBuilder.Entity<Appointment>().ToTable("APPOINTMENTS");
        modelBuilder.Entity<MedicalRecord>().ToTable("MEDICAL_RECORDS");
        modelBuilder.Entity<AuditLog>().ToTable("AUDIT_LOGS");

        // Seed default admin user
        modelBuilder.Entity<User>().HasData(new User
        {
            Id = 1,
            Username = "admin",
            PasswordHash = "admin123", // Weak default credential
            FullName = "System Administrator",
            Role = "Admin",
            Email = "admin@healthcorp.local",
            IsActive = true
        });
    }
}
