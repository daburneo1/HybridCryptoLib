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
            var publicKey = RsaUtils.ReadPublicKey(publicKeyPath);

            var result = _encryptionFacade.EncryptData(jsonData, hash, publicKey);

            Assert.NotNull(result.EncryptedData);
            Assert.NotNull(result.EncryptedHash);
        }

        [Fact]
        public void DecryptData_ValidInput_ReturnsDecryptedData()
        {
            var jsonData = "{\"name\":\"TV\",\"price\":\"500\"}";
            var hash = "HashTest";
            var publicKeyPath = "C:\\Users\\davb9\\.ssh\\id_rsa_pub.pem";
            var privateKeyPath = "C:\\Users\\davb9\\.ssh\\id_rsa_pkcs8.pem";
            var publicKey = RsaUtils.ReadPublicKey(publicKeyPath);
            var privateKey = RsaUtils.ReadPrivateKey(privateKeyPath);

            var encryptedResult = _encryptionFacade.EncryptData(jsonData, hash, publicKey);
            var decryptedData = _encryptionFacade.DecryptData("vqngQLmyc4Se+EiuqdGKmg==;+g1lLRYoOyz1hr3zn3jAZeSGwe0LL0LjlFyXlFxSSHQ=", "ecirNfOWHVnyhS86QjqdKMpH+Tdwnf089bQcsM2F3bCOvR/LXl0wEhFE4w9pgCtufZEow8DLBDhZQ9TiqusUc2ZuzjiMIysexp0avfKK8O8h8vZynQpLvTnRebtnreSM3dz+4uvFu6RILXr3sIdztwS5NA3sjs+8TRT6vH2MC4IkAPzg2BJNf1sJyjW4EdaUOSs/8IkfuH8FnES8iifTs2Da2Ckcnv5iETw3890Dwt7j+DZeBaPvuWr0I4NUHMyUDC0e4Dn2/vo8JL2Imu1dXHakiRryfkF8S66VQXgHh83dHx7C1+kIw2Uo0/F/SSeC2KXNs/MtpCTiMfhcujc6sQ==", privateKey);

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
            var plainText = "ae9d46271f78f817e59cbb1d0b0568ee";
            var publicKeyPath = "C:\\Users\\davb9\\.ssh\\id_rsa_pub.pem";
            var publicKey = RsaUtils.ReadPublicKey(publicKeyPath);

            var dataBytes = Encoding.UTF8.GetBytes(plainText);
            var rsaAlgorithm = new RsaEncryptionAlgorithm();
            
            var encryptedData = rsaAlgorithm.Encrypt(dataBytes, publicKey);

            Assert.NotNull(encryptedData);
            Assert.NotEmpty(encryptedData.Data);
            var encryptedDataBytes = Encoding.UTF8.GetBytes(encryptedData.Data);
            var encryptedDataString = Convert.ToBase64String(encryptedDataBytes);
            Assert.NotEmpty(encryptedDataString);
        }

        [Fact]
        public void RsaDecryptData_ValidInput_ReturnsDecryptedData()
        {
            var plainText = "ae9d46271f78f817e59cbb1d0b0568ee";
            
            var publicKeyPath = "C:\\Users\\davb9\\.ssh\\id_rsa_pub.pem";
            var privateKeyPath = "C:\\Users\\davb9\\.ssh\\id_rsa_pkcs8.pem";
            var publicKey = RsaUtils.ReadPublicKey(publicKeyPath);
            var privateKey = RsaUtils.ReadPrivateKey(privateKeyPath);

            var dataBytes = Encoding.UTF8.GetBytes(plainText);
            var rsaAlgorithm = new RsaEncryptionAlgorithm();

            var encryptedData = rsaAlgorithm.Encrypt(dataBytes, publicKey);
    
            // Asegúrate de que los datos cifrados no sean nulos o vacíos
            Assert.NotNull(encryptedData);
            Assert.True(encryptedData.IsEncrypted);
            Assert.NotEmpty(encryptedData.Data);

            var decryptedData = rsaAlgorithm.Decrypt(encryptedData, privateKey);
            var decryptedText = Encoding.UTF8.GetString(decryptedData);
    
            Assert.Equal(plainText, decryptedText);
        }
    }
}