using System.Security.Cryptography;
using System.Text;

namespace HybridCryptoLib.Domain
{
    public class EncryptionKey(string key, string pem)
    {
        public string Key { get; } = key;
        public string Pem { get; } = pem;

        public byte[] KeyBytes => Encoding.UTF8.GetBytes(Key);
        public string Value => Key;
    }


    public static class RsaKeyGenerator
    {
        public static string GenerateRsaPublicKeyX509(string seed)
        {
            using var rsa = new RSACryptoServiceProvider(2048);
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            return Convert.ToBase64String(publicKey);
        }

        public static string GenerateRsaPrivateKeyPkcs8(string seed)
        {
            using var rsa = new RSACryptoServiceProvider(2048);
            var privateKey = rsa.ExportPkcs8PrivateKey();
            return Convert.ToBase64String(privateKey);
        }

        public static (string PublicKey, string PrivateKey) GenerateRsaKeys(string seed)
        {
            using var rsa = new RSACryptoServiceProvider(2048);

            // Generar la clave privada en formato PKCS#8
            var privateKey = rsa.ExportPkcs8PrivateKey();
            var privateKeyString = Convert.ToBase64String(privateKey);

            // Generar la clave pública en formato X.509
            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            var publicKeyString = Convert.ToBase64String(publicKey);

            return (publicKeyString, privateKeyString);
        }
    }
}