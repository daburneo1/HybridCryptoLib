namespace HybridCryptoLib.Application.interfaces
{
    public interface IEncryptionService
    {
        (byte[] EncryptedData, byte[] EncryptedHash) EncryptData(string plainText, string hash, string publicKey);
        string DecryptData(byte[] encryptedData, byte[] encryptedHash, string privateKey);
    }
}