using System.Security.Cryptography;
using Application.interfaces;
using Domain;
using System.Text;

namespace Infrastructure;

public class RsaEncryptionAlgorithm : IEncryptionAlgorithm
{
    public EncryptedData Encrypt(byte[] data, EncryptionKey key)
    {
        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.FromXmlString(key.Key);
            var encryptedData = rsa.Encrypt(data, true);
            return new EncryptedData(encryptedData, true);
        }
    }

    public byte[] Decrypt(EncryptedData encryptedData, EncryptionKey key)
    {
        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.FromXmlString(key.Key);
            return rsa.Decrypt(encryptedData.Data, true);
        }
    }
}