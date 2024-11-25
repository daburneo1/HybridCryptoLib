using System.Text;
using HybridCryptoLib;
using HybridCryptoLib.Application.interfaces;
using HybridCryptoLib.Application.services;
using HybridCryptoLib.Application.Utilities;
using HybridCryptoLib.Infrastructure.Algorithm;
using Xunit;

namespace Tests
{
    public class EncryptionFacadeIntegrationTests
    {
        private readonly IEncryptionService _encryptionService;
        private readonly EncryptionFacade _encryptionFacade;

        public EncryptionFacadeIntegrationTests()
        {
            // Configure the actual implementations of the encryption algorithms
            IEncryptionAlgorithm aesAlgorithm = new AesEncryptionAlgorithm();
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
            var publicKeyPath = "C:\\Users\\davb9\\.ssh\\id_rsa_pub.pem";
            var publicKey = RsaKeyReader.ReadPublicKey(publicKeyPath);

            var result = _encryptionFacade.EncryptData(jsonData, hash, publicKey);

            Assert.NotNull(result.EncryptedData);
            Assert.NotNull(result.EncryptedHash);
        }

        [Fact]
        public void DecryptData_ValidInput_ReturnsDecryptedData()
        {
            var jsonData = "Hello World!!!";
            var hash = "HashTest";
            var publicKeyPath = "C:\\Users\\davb9\\.ssh\\id_rsa_pub.pem";
            var privateKeyPath = "C:\\Users\\davb9\\.ssh\\id_rsa_pkcs8.pem";
            var publicKey = RsaKeyReader.ReadPublicKey(publicKeyPath);
            var privateKey = RsaKeyReader.ReadPrivateKey(privateKeyPath);

            var encryptedResult = _encryptionFacade.EncryptData(jsonData, hash, publicKey);
            var decryptedData = _encryptionFacade.DecryptData(encryptedResult.EncryptedData, encryptedResult.EncryptedHash, privateKey);

            Assert.Equal(jsonData, decryptedData);
        }

        [Fact]
        public void AesEncryptData_ValidInput_ReturnsEncryptedData()
        {
            var plainText = "Hello World!!!";
            var key = "AesTestKey";

            var dataBytes = Encoding.UTF8.GetBytes(plainText);
            var aesAlgorithm = new AesEncryptionAlgorithm();
            var encryptedData = aesAlgorithm.Encrypt(dataBytes, key);

            Assert.NotNull(encryptedData);
            Assert.NotEmpty(encryptedData.Data);
        }

        [Fact]
        public void AesDecryptData_ValidInput_ReturnsDecryptedData()
        {
            var plainText = "Hello World!!!";
            var key = "AesTestKey";

            var dataBytes = Encoding.UTF8.GetBytes(plainText);
            var aesAlgorithm = new AesEncryptionAlgorithm();
            var encryptedData = aesAlgorithm.Encrypt(dataBytes, key);
            var decryptedData = aesAlgorithm.Decrypt(encryptedData, key);

            var decryptedText = Encoding.UTF8.GetString(decryptedData);
            Assert.Equal(plainText, decryptedText);
        }

        [Fact]
        public void RsaEncryptData_ValidInput_ReturnsEncryptedData()
        {
            var plainText = "Hello World!!!";
            var publicKeyPath = "C:\\Users\\davb9\\.ssh\\id_rsa_pub.pem";
            var publicKey = RsaKeyReader.ReadPublicKey(publicKeyPath);

            var dataBytes = Encoding.UTF8.GetBytes(plainText);
            var rsaAlgorithm = new RsaEncryptionAlgorithm();
            
            var encryptedData = rsaAlgorithm.Encrypt(dataBytes, publicKey);

            Assert.NotNull(encryptedData);
            Assert.NotEmpty(encryptedData.Data);
            var encryptedDataString = Convert.ToBase64String(encryptedData.Data);
            Assert.NotEmpty(encryptedDataString);
        }

        [Fact]
        public void RsaDecryptData_ValidInput_ReturnsDecryptedData()
        {
            var plainText = "Hello World!!!";
            
            var publicKeyPath = "C:\\Users\\davb9\\.ssh\\id_rsa_pub.pem";
            var privateKeyPath = "C:\\Users\\davb9\\.ssh\\id_rsa_pkcs8.pem";
            var publicKey = RsaKeyReader.ReadPublicKey(publicKeyPath);
            var privateKey = RsaKeyReader.ReadPrivateKey(privateKeyPath);

            var dataBytes = Encoding.UTF8.GetBytes(plainText);
            var rsaAlgorithm = new RsaEncryptionAlgorithm();

            var encryptedData = rsaAlgorithm.Encrypt(dataBytes, publicKey);
    
            // Asegúrate de que los datos cifrados no sean nulos o vacíos
            Assert.NotNull(encryptedData);
            Assert.True(encryptedData.IsValid);
            Assert.NotEmpty(encryptedData.Data);

            var decryptedData = rsaAlgorithm.Decrypt(encryptedData, privateKey);
            var decryptedText = Encoding.UTF8.GetString(decryptedData);
    
            Assert.Equal(plainText, decryptedText);
        }
    }
}