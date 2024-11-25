using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Application.interfaces;
using Domain;

namespace Infrastructure
{
    public class RsaEncryptionAlgorithm : IEncryptionAlgorithm
    {
        public EncryptedData Encrypt(byte[] data, string key)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                var publicKeyBytes = ExtractPublicKeyFromPem(key);
                rsa.ImportRSAPublicKey(publicKeyBytes, out _);

                var encryptedData = rsa.Encrypt(data, false); // false para PKCS#1 v1.5
                return new EncryptedData(encryptedData, true);
            }
        }

        private static byte[] ExtractPublicKeyFromPem(string pem)
        {
            var pemHeader = "-----BEGIN RSA PUBLIC KEY-----";
            var pemFooter = "-----END RSA PUBLIC KEY-----";

            var start = pem.IndexOf(pemHeader, StringComparison.Ordinal) + pemHeader.Length;
            var end = pem.IndexOf(pemFooter, start, StringComparison.Ordinal);

            var base64 = pem.Substring(start, end - start).Replace("\n", "").Replace("\r", "");
            return Convert.FromBase64String(base64);
        }

        private static byte[] ExtractPrivateKeyFromPem(string pem)
        {
            var pemHeader = "-----BEGIN PRIVATE KEY-----";
            var pemFooter = "-----END PRIVATE KEY-----";

            var start = pem.IndexOf(pemHeader, StringComparison.Ordinal) + pemHeader.Length;
            var end = pem.IndexOf(pemFooter, start, StringComparison.Ordinal);

            var base64 = pem.Substring(start, end - start).Replace("\n", "").Replace("\r", "");
            return Convert.FromBase64String(base64);
        }

        public byte[] Decrypt(EncryptedData encryptedData, string key)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                var privateKeyBytes = ExtractPrivateKeyFromPem(key);
                rsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

                return rsa.Decrypt(encryptedData.Data, false); // false for PKCS#1 v1.5
            }
        }
    }
}