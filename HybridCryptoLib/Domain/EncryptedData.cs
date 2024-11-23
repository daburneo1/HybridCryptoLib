namespace Domain;

public class EncryptedData
{
    public byte[] Data { get; }
    public bool IsValid { get; }

    public EncryptedData(byte[] data, bool isValid)
    {
        Data = data;
        IsValid = isValid;
    }
}