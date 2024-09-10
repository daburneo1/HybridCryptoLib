using System.Security.Cryptography;
using Application.interfaces;
using Domain;

namespace Infrastructure;

public class RsaEncryption : IEncryptionAlgorithm
{
    public EncryptedData Encrypt(byte[] data, EncryptionKey key)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(key.Key.ToCharArray());
        byte[] encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        return new EncryptedData(encrypted, true);
    }

    public byte[] Decrypt(EncryptedData encryptedData, EncryptionKey key)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(key.Key.ToCharArray());
        return rsa.Decrypt(encryptedData.Data, RSAEncryptionPadding.OaepSHA256);
    }
}