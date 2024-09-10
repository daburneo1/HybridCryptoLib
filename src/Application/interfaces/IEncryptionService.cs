using Domain;

namespace Application.interfaces;

public interface IEncryptionService
{
    EncryptedData EncryptData(byte[] data, EncryptionKey publicKey);
    byte[] DecryptData(EncryptedData encryptedData, EncryptionKey privateKey);
}