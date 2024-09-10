using System.Security.Cryptography;
using System.Text;
using Application.interfaces;
using Domain;

namespace Infrastructure;

public class AesEncryption : IEncryptionAlgorithm
{
    public EncryptedData Encrypt(byte[] data, EncryptionKey key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key.Key);
            aes.GenerateIV();
            aes.Mode = CipherMode.CBC;

            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            {
                byte[] encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);
                return new EncryptedData(encrypted, true);
            }
        }
    }

    public byte[] Decrypt(EncryptedData encryptedData, EncryptionKey key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key.Key);
            aes.Mode = CipherMode.CBC;

            using (ICryptoTransform decryptor = aes.CreateDecryptor())
            {
                return decryptor.TransformFinalBlock(encryptedData.Data, 0, encryptedData.Data.Length);
            }
        }
    }
}