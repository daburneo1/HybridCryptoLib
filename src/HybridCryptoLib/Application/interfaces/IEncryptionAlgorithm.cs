using HybridCryptoLib.Domain;

namespace HybridCryptoLib.Application.interfaces;

public interface IEncryptionAlgorithm
{
    EncryptedData Encrypt(byte[] data, string key);
    byte[] Decrypt(EncryptedData encryptedData, string key);
}