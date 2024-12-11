﻿using System.Text;
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
            var decryptedData = _encryptionFacade.DecryptData("WUGp9SlKP66OUVnWlyD+aKnzXt1QxoEjkAUSh9n+z7BbRyA1VTxqNFWK4R173YRX", "RIqpm0L7DJqz4L3VAY0AD5Q6QFdVCJjkB05qSnp29QlTRpsYhavGQL8OirTFa6VpG3Gq3DzR082KqUUWZmaUUy04vV/LOfewbxn2csy3HWvvfZznPwwTyKRugErC2NT8CoGEh0PaR46yTlYTZa//m28Z4PWqZa0GsuKwcHpjw8M8QPQyt0qNBRIStZO9ZsE80v9/5y3rOqCi9DLVZRVx4AMMnHA24JD2fxIajCTMxqOKyAKBzWy2WlxQZ9hs+n2rAzj1EQhy4A++aedxqccLN6rdZfm9RgYv1m0w3umRq4O/QRCGUIyqRVnIU3/XupARQ1cU59mSnu00D9L2eGVtWA==", privateKey);

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