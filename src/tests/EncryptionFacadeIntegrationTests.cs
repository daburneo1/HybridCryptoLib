using Application.interfaces;
using Application.services;
using Domain;
using WebAPI;
using Xunit;
using Infrastructure;

namespace Tests;

public class EncryptionFacadeIntegrationTests
{
    private readonly IEncryptionService _encryptionService;
    private readonly EncryptionFacade _encryptionFacade;

    public EncryptionFacadeIntegrationTests()
    {
        // Configure the actual implementations of the encryption algorithms
        IEncryptionAlgorithm aesAlgorithm = new AesEncryption();
        IEncryptionAlgorithm rsaAlgorithm = new RsaEncryptionAlgorithm();

        // Use these implementations in HybridEncryptionService
        _encryptionService = new HybridEncryptionService(aesAlgorithm, rsaAlgorithm);
        _encryptionFacade = new EncryptionFacade(_encryptionService);
    }

    [Fact]
    public void EncryptData_ValidInput_ReturnsEncryptedDataAndHash()
    {
        var jsonData = "Hello World!!!";
        var hash = "HashTest";
        var seed = "publicKeySeed";
        var publicKeyXml = RsaKeyGenerator.GenerateRsaKeyXml(seed, false); // Generate public key
        var publicKey = new EncryptionKey(publicKeyXml, "RSA");

        var result = _encryptionFacade.EncryptData(jsonData, hash, publicKey);

        Assert.NotNull(result.EncryptedData);
        Assert.NotNull(result.EncryptedHash);
    }

    [Fact]
    public void DecryptData_ValidInput_ReturnsDecryptedData()
    {
        var jsonData = "Hello World!!!";
        var hash = "HashTest";
        var publicKeySeed = "publicKeySeed";
        var privateKeySeed = "privateKeySeed";
        var publicKeyXml = RsaKeyGenerator.GenerateRsaKeyXml(publicKeySeed, false); // Generate public key
        var privateKeyXml = RsaKeyGenerator.GenerateRsaKeyXml(privateKeySeed, true); // Generate private key
        var publicKey = new EncryptionKey(publicKeyXml, "RSA");
        var privateKey = new EncryptionKey(privateKeyXml, "RSA");

        var encryptedResult = _encryptionFacade.EncryptData(jsonData, hash, publicKey);
        var decryptedData = _encryptionFacade.DecryptData(encryptedResult.EncryptedData, encryptedResult.EncryptedHash, privateKey);

        Assert.Equal(jsonData, decryptedData);
    }
}