using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace HealthCorp.Legacy;

public static class SerializationHelper
{
    // VULNERABILITY: Insecure Deserialization (BinaryFormatter is deprecated and dangerous)
    // "Hard" version because it might be wrapped in a generic name like "DeepClone" or "RestoreState"
    // and misleadingly commented.
    
    [Obsolete("Use newer JSON serializers")]
#pragma warning disable SYSLIB0011 // BinaryFormatter is obsolete and should not be used
    public static object RestoreState(byte[] data)
    {
        // "Safe" wrapper checks?
        if (data == null || data.Length == 0) return new object();

        // DANGEROUS:
        BinaryFormatter formatter = new BinaryFormatter();
        using (MemoryStream ms = new MemoryStream(data))
        {
            return formatter.Deserialize(ms);
        }
    }

    public static byte[] SaveState(object obj)
    {
        BinaryFormatter formatter = new BinaryFormatter();
        using (MemoryStream ms = new MemoryStream())
        {
            formatter.Serialize(ms, obj);
            return ms.ToArray();
        }
    }
}
