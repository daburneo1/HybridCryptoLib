namespace Domain;

public class EncryptedData(byte[] data, bool isEncrypted)
{
    public byte[] Data { get; } = data;
    public bool IsEncrypted { get; } = isEncrypted; // Indica si los datos están encriptados
}