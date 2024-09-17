using System.Security.Cryptography;
using System.Text;
using Application.interfaces;
using Domain;

namespace Application.services
{
    public class HybridEncryptionService : IEncryptionService
    {
        private readonly IEncryptionAlgorithm aesAlgorithm;
        private readonly IEncryptionAlgorithm rsaAlgorithm;

        public HybridEncryptionService(IEncryptionAlgorithm aesAlgorithm, IEncryptionAlgorithm rsaAlgorithm)
        {
            this.aesAlgorithm = aesAlgorithm;
            this.rsaAlgorithm = rsaAlgorithm;
        }

        public (byte[] EncryptedData, byte[] EncryptedHash) EncryptData(string plainText, string hash, EncryptionKey publicKey)
        {
            // Encrypt plain text with AES
            var dataBytes = Encoding.UTF8.GetBytes(plainText);
            var aesEncryptedData = aesAlgorithm.Encrypt(dataBytes, publicKey);

            // Hash the plain text with SHA256
            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(hash));

            // Encrypt the hash with RSA
            var rsaEncryptedHash = rsaAlgorithm.Encrypt(hashBytes, publicKey);

            return (aesEncryptedData.Data, rsaEncryptedHash.Data);
        }

        public string DecryptData(byte[] encryptedData, byte[] encryptedHash, EncryptionKey privateKey)
        {
            // Decrypt the hash with RSA
            var decryptedHash = rsaAlgorithm.Decrypt(new EncryptedData(encryptedHash, true), privateKey);

            // Decrypt the data with AES using the decrypted hash
            var aesDecryptedData = aesAlgorithm.Decrypt(new EncryptedData(encryptedData, true), new EncryptionKey(Encoding.UTF8.GetString(decryptedHash), "AES"));

            return Encoding.UTF8.GetString(aesDecryptedData);
        }
    }
}