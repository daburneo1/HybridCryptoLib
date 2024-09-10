using Application.interfaces;
using Domain;

namespace Application.services;

public class HybridEncryptionService(IEncryptionAlgorithm aesAlgorithm, IEncryptionAlgorithm rsaAlgorithm)
    : IEncryptionService
{
    public byte[] EncryptData(byte[] data, EncryptionKey publicKey)
    {
        var aesEncryptedData = aesAlgorithm.Encrypt(data, publicKey);
        var rsaEncryptedData = rsaAlgorithm.Encrypt(aesEncryptedData.Data, publicKey);
        return rsaEncryptedData.Data;
    }

    public byte[] DecryptData(EncryptedData encryptedData, EncryptionKey privateKey)
    {
        if (!encryptedData.IsEncrypted)
        {
            return encryptedData.Data;
        }

        var rsaDecryptedData = rsaAlgorithm.Decrypt(encryptedData, privateKey);
        return aesAlgorithm.Decrypt(new EncryptedData(rsaDecryptedData, false), privateKey);
    }
}