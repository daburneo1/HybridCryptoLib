using Application.interfaces;
using Domain;

namespace WebAPI;

public class EncryptionFacade
{
    private readonly IEncryptionService _encryptionService;

    public EncryptionFacade(IEncryptionService encryptionService)
    {
        _encryptionService = encryptionService;
    }

    public EncryptedData EncryptData(byte[] data, EncryptionKey publicKey)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        return _encryptionService.EncryptData(data, publicKey);
    }

    public byte[] DecryptData(EncryptedData encryptedData, EncryptionKey privateKey)
    {
        if (encryptedData == null) throw new ArgumentNullException(nameof(encryptedData));
        return _encryptionService.DecryptData(encryptedData, privateKey);
    }
}