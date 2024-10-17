using System.Security.Cryptography;
using System.Text;
using Application.interfaces;
using Domain;

namespace Infrastructure;

public class AesEncryption : IEncryptionAlgorithm
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
                return new EncryptedData(result, true);
            }
        }
    }

    public byte[] Decrypt(EncryptedData encryptedData, string key)
    {
        var keyBytes = SHA512.HashData(Encoding.UTF8.GetBytes(key));
        using (var aes = Aes.Create())
        {
            aes.Key = keyBytes.Take(32).ToArray(); // Use the first 32 bytes of the SHA-512 hash
            aes.Padding = PaddingMode.PKCS7; // Ensure consistent padding mode
            var iv = new byte[aes.BlockSize / 8];
            var cipherText = new byte[encryptedData.Data.Length - iv.Length];
            Buffer.BlockCopy(encryptedData.Data, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(encryptedData.Data, iv.Length, cipherText, 0, cipherText.Length);
            aes.IV = iv;
            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
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