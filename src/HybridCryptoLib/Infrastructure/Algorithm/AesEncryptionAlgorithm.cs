using System.Security.Cryptography;
using System.Text;
using HybridCryptoLib.Application.interfaces;
using HybridCryptoLib.Domain;

namespace HybridCryptoLib.Infrastructure.Algorithm;

public class AesEncryptionAlgorithm : IEncryptionAlgorithm
{
    public EncryptedData Encrypt(byte[] data, string key)
    {
        var keyBytes = SHA512.HashData(Encoding.UTF8.GetBytes(key));
        using (var aes = Aes.Create())
        {
            aes.Key = keyBytes.Take(32).ToArray(); // Use the first 32 bytes of the SHA-512 hash
            aes.GenerateIV();
            aes.Padding = PaddingMode.PKCS7; // Ensure consistent padding mode
            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            {
                var encryptedData = PerformCryptography(data, encryptor);
                var result = new byte[aes.IV.Length + encryptedData.Length];
                Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
                Buffer.BlockCopy(encryptedData, 0, result, aes.IV.Length, encryptedData.Length);
                return new EncryptedData(Convert.ToBase64String(result), true);
            }
        }
    }

    public byte[] Decrypt(EncryptedData encryptedData, string key)
    {
        var parts = encryptedData.Data.Split(';');
        if (parts.Length != 2)
        {
            throw new FormatException("Invalid encrypted data format. Expected IV and cipher text separated by ':'.");
        }

        // Decodifica IV y datos cifrados desde Base64
        var iv = Convert.FromBase64String(parts[0]);
        var cipherText = Convert.FromBase64String(parts[1]);

        // Verifica tamaños
        if (iv.Length != 16)
        {
            throw new CryptographicException("Invalid IV length. Expected 16 bytes.");
        }

        // Decodifica la clave AES
        var keyBytes = Encoding.UTF8.GetBytes(key);
        if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
        {
            throw new CryptographicException("Invalid AES key length.");
        }

        // Configura AES
        using (var aes = Aes.Create())
        {
            aes.Key = keyBytes;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7; // Debe coincidir con el cliente

            using (var decryptor = aes.CreateDecryptor())
            {
                return PerformCryptography(cipherText, decryptor);
            }
        }
    }

    private static byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
    {
        using (var memoryStream = new MemoryStream())
        {
            using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();
            }
            return memoryStream.ToArray();
        }
    }
}