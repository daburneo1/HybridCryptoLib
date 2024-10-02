using System.Security.Cryptography;
using Application.interfaces;
using Domain;

namespace Infrastructure
{
    public class RsaEncryptionAlgorithm : IEncryptionAlgorithm
    {
        public EncryptedData Encrypt(byte[] data, string publicKeyX509)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                var publicKeyBytes = Convert.FromBase64String(publicKeyX509);
                rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

                var encryptedData = rsa.Encrypt(data, false); // false para PKCS#1 v1.5
                return new EncryptedData(encryptedData, true);
            }
        }

        public byte[] Decrypt(EncryptedData encryptedData, string privateKeyPkcs8)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                var privateKeyBytes = Convert.FromBase64String(privateKeyPkcs8);
                rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

                return rsa.Decrypt(encryptedData.Data, false); // false para PKCS#1 v1.5
            }
        }
    }
}