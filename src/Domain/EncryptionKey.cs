using System.Security.Cryptography;
using System.Text;

namespace Domain
{
    public class EncryptionKey
    {
        public string Key { get; }
        public string Pem { get; }

        public EncryptionKey(string key, string pem)
        {
            Key = key;
            Pem = pem;
        }

        public byte[] KeyBytes => Encoding.UTF8.GetBytes(Key);
        public string Value => Key;
    }
    
    
    public static class RsaKeyGenerator
    {
        public static string GenerateRsaKeyXml(string seed, bool includePrivateParameters)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                // Derive a key from the seed
                var seedBytes = Encoding.UTF8.GetBytes(seed);
                var derivedBytes = new Rfc2898DeriveBytes(seedBytes, seedBytes, 100000, HashAlgorithmName.SHA256);
                var keyBytes = derivedBytes.GetBytes(2048 / 8);

                // Generate RSA key parameters
                var rsaParameters = rsa.ExportParameters(includePrivateParameters);
                rsaParameters.Modulus = keyBytes;

                rsa.ImportParameters(rsaParameters);
                return rsa.ToXmlString(includePrivateParameters); // Export the key in XML format
            }
        }
    }
}