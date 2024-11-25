using System.Text;
using HybridCryptoLib.Application.interfaces;
using HybridCryptoLib.Domain;

namespace HybridCryptoLib.Application.services
{
    public class HybridEncryptionService(IEncryptionAlgorithm aesAlgorithm, IEncryptionAlgorithm rsaAlgorithm)
        : IEncryptionService
    {
        public (byte[] EncryptedData, byte[] EncryptedHash) EncryptData(string plainText, string hashKey, string publicKeyX509)
        {
            // Encrypt plain text with AES
            var dataBytes = Encoding.UTF8.GetBytes(plainText);
            var aesEncryptedData = aesAlgorithm.Encrypt(dataBytes, hashKey);

            // Hash the plain text with SHA256
            var hashBytes = Encoding.UTF8.GetBytes(hashKey);
                
            // Encrypt the hash with RSA
            var rsaEncryptedHash = rsaAlgorithm.Encrypt(hashBytes, publicKeyX509);

            return (aesEncryptedData.Data, rsaEncryptedHash.Data);
        }

        public string DecryptData(byte[] encryptedData, byte[] encryptedHash, string privateKey)
        {
            // Decrypt the hash with RSA
            var decryptedHash = rsaAlgorithm.Decrypt(new EncryptedData(encryptedHash, true), privateKey);
            // Decrypt the data with AES using the decrypted hash
            var aesDecryptedData = aesAlgorithm.Decrypt(new EncryptedData(encryptedData, true), Encoding.UTF8.GetString(decryptedHash));

            return Encoding.UTF8.GetString(aesDecryptedData);
        }
    }
}