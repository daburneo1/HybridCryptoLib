using System.Security.Cryptography;
using HybridCryptoLib.Application.interfaces;
using HybridCryptoLib.Domain;
using static HybridCryptoLib.Application.Utilities.RsaUtils;


namespace HybridCryptoLib.Infrastructure.Algorithm
{
    public class RsaEncryptionAlgorithm : IEncryptionAlgorithm
    {
        public EncryptedData Encrypt(byte[] data, string key)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                var publicKeyBytes = ExtractPublicKeyFromPem(key);
                rsa.ImportRSAPublicKey(publicKeyBytes, out _);

                var encryptedData = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1); 
                return new EncryptedData(Convert.ToBase64String(encryptedData), true);
            }
        }

        public byte[] Decrypt(EncryptedData encryptedData, string key)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                var privateKeyBytes = ExtractPrivateKeyFromPem(key);
                rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

                var encryptedDataBytes = Convert.FromBase64String(encryptedData.Data);
                return rsa.Decrypt(encryptedDataBytes, RSAEncryptionPadding.Pkcs1); // Usar PKCS#1 v1.5
            }
        }
    }
}