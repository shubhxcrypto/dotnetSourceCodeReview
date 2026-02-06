using System;
using System.Collections.Generic;

namespace HealthCorp.Core.Entities;

public class Patient
{
    public int Id { get; set; }
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public DateTime DateOfBirth { get; set; }
    public string SSN { get; set; } = string.Empty; // Sensitive PII
    public string Address { get; set; } = string.Empty;
    public string InsuranceProvider { get; set; } = string.Empty;
    
    // Navigation properties
    public ICollection<Appointment> Appointments { get; set; } = new List<Appointment>();
    public ICollection<MedicalRecord> MedicalRecords { get; set; } = new List<MedicalRecord>();
}
