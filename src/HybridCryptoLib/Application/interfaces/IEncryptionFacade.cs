namespace HybridCryptoLib.Application.interfaces
{
    public interface IEncryptionFacade
    {
        (string EncryptedData, string EncryptedHash) EncryptData(string jsonData, string hash, string publicKeyX509);
        string DecryptData(string encryptedData, string encryptedHash, string privateKey);
    }
}