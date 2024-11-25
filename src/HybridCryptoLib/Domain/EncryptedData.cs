namespace HybridCryptoLib.Domain;

public class EncryptedData(byte[] data, bool isValid)
{
    public byte[] Data { get; } = data;
    public bool IsValid { get; } = isValid;
}