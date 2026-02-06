using System;

namespace HealthCorp.Core.Entities;

public class MedicalRecord
{
    public int Id { get; set; }
    public int PatientId { get; set; }
    public Patient Patient { get; set; } = null!;
    public string RecordType { get; set; } = "General"; // Lab, Scan, Prescription
    public string Description { get; set; } = string.Empty;
    public string? FilePath { get; set; } // Path on disk
    public string? ContentType { get; set; } 
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public int CreatedByUserId { get; set; }
}
