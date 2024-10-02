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

        public (byte[] EncryptedData, byte[] EncryptedHash) EncryptData(string plainText, string hashKey, string publicKeyX509)
        {
            // Encrypt plain text with AES
            var dataBytes = Encoding.UTF8.GetBytes(plainText);
            var aesEncryptedData = aesAlgorithm.Encrypt(dataBytes, hashKey);

            // Hash the plain text with SHA256
            var hashBytes = SHA512.HashData(Encoding.UTF8.GetBytes(hashKey));

            // Encrypt the hash with RSA
            var rsaEncryptedHash = rsaAlgorithm.Encrypt(hashBytes, publicKeyX509);

            return (aesEncryptedData.Data, rsaEncryptedHash.Data);
        }

        public string DecryptData(byte[] encryptedData, byte[] encryptedHash, string privateKey)
        {
            // Convert the PKCS8 formatted private key to RSAParameters
            var privateKeyBytes = Convert.FromBase64String(privateKey);
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

            // Decrypt the hash with RSA
            var decryptedHash = rsaAlgorithm.Decrypt(new EncryptedData(encryptedHash, true), privateKey);

            // Decrypt the data with AES using the decrypted hash
            var aesDecryptedData = aesAlgorithm.Decrypt(new EncryptedData(encryptedData, true), Encoding.UTF8.GetString(decryptedHash));

            return Encoding.UTF8.GetString(aesDecryptedData);
        }
    }
}