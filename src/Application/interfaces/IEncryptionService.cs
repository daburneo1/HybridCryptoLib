using Domain;

namespace Application.interfaces
{
    public interface IEncryptionService
    {
        (byte[] EncryptedData, byte[] EncryptedHash) EncryptData(string plainText, string hash, EncryptionKey publicKey);
        string DecryptData(byte[] encryptedData, byte[] encryptedHash, EncryptionKey privateKey);
    }
}