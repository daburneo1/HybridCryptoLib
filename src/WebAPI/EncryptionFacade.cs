using System.Text;
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

    public (string EncryptedData, string EncryptedHash) EncryptData(string jsonData, string hash, EncryptionKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(jsonData);
        var result = _encryptionService.EncryptData(jsonData, hash, publicKey);
        var encryptedData = Convert.ToBase64String(result.EncryptedData);
        var encryptedHash = Convert.ToBase64String(result.EncryptedHash);
        return (encryptedData, encryptedHash);
    }

    public string DecryptData(string encryptedData, string encryptedHash, EncryptionKey privateKey)
    {
        if (encryptedData == null) throw new ArgumentNullException(nameof(encryptedData));
        if (encryptedHash == null) throw new ArgumentNullException(nameof(encryptedHash));
        
        var encryptedDataBytes = Convert.FromBase64String(encryptedData);
        var encryptedHashBytes = Convert.FromBase64String(encryptedHash);
        
        var decryptedData = _encryptionService.DecryptData(encryptedDataBytes, encryptedHashBytes, privateKey);
        return decryptedData;
    }
}