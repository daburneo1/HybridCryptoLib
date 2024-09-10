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

    public string EncryptData(byte[] data, EncryptionKey publicKey)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        var encryptedData = _encryptionService.EncryptData(data, publicKey);
        return Convert.ToBase64String(encryptedData);
    }

    public byte[] DecryptData(string encryptedData, EncryptionKey privateKey)
    {
        if (encryptedData == null) throw new ArgumentNullException(nameof(encryptedData));
        var encryptedBytes = Convert.FromBase64String(encryptedData);
        return _encryptionService.DecryptData(new EncryptedData(encryptedBytes, true), privateKey);
    }
}