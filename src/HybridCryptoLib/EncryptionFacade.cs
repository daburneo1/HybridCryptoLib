using HybridCryptoLib.Application.interfaces;

namespace HybridCryptoLib
{
    public class EncryptionFacade(IEncryptionService encryptionService)
    {
        public (string EncryptedData, string EncryptedHash) EncryptData(string jsonData, string hash, string publicKeyX509)
        {
            ArgumentNullException.ThrowIfNull(jsonData);
            var result = encryptionService.EncryptData(jsonData, hash, publicKeyX509);
            var encryptedData = Convert.ToBase64String(result.EncryptedData);
            var encryptedHash = Convert.ToBase64String(result.EncryptedHash);
            return (encryptedData, encryptedHash);
        }

        public string DecryptData(string encryptedData, string encryptedHash, string privateKey)
        {
            if (encryptedData == null) throw new ArgumentNullException(nameof(encryptedData));
            if (encryptedHash == null) throw new ArgumentNullException(nameof(encryptedHash));
            
            var encryptedDataBytes = Convert.FromBase64String(encryptedData);
            var encryptedHashBytes = Convert.FromBase64String(encryptedHash);
            
            var decryptedData = encryptionService.DecryptData(encryptedDataBytes, encryptedHashBytes, privateKey);
            return decryptedData;
        }
    }
}