using Domain;

namespace Application.interfaces;

public interface IEncryptionAlgorithm
{
    EncryptedData Encrypt(byte[] data, EncryptionKey key);
    byte[] Decrypt(EncryptedData encryptedData, EncryptionKey key);
}