
namespace Tests
{
    using Xunit;
    using Moq;
    using Application.interfaces;
    using Domain;
    using WebAPI;
    using System;

    public class EncryptionFacadeTests
    {
        private readonly Mock<IEncryptionService> _mockEncryptionService;
        private readonly EncryptionFacade _encryptionFacade;

        public EncryptionFacadeTests()
        {
            _mockEncryptionService = new Mock<IEncryptionService>();
            _encryptionFacade = new EncryptionFacade(_mockEncryptionService.Object);
        }

        [Fact]
        public void EncryptData_ValidInput_ReturnsEncryptedDataAndHash()
        {
            var jsonData = "test data";
            var hash = "test hash";
            var publicKey = new EncryptionKey("publicKey", "keyType");
            var encryptedData = new byte[] { 1, 2, 3 };
            var encryptedHash = new byte[] { 4, 5, 6 };

            _mockEncryptionService
                .Setup(s => s.EncryptData(jsonData, hash, publicKey))
                .Returns((encryptedData, encryptedHash));

            var result = _encryptionFacade.EncryptData(jsonData, hash, publicKey);

            Assert.Equal(Convert.ToBase64String(encryptedData), result.EncryptedData);
            Assert.Equal(Convert.ToBase64String(encryptedHash), result.EncryptedHash);
        }

        [Fact]
        public void EncryptData_NullJsonData_ThrowsArgumentNullException()
        {
            var hash = "test hash";
            var publicKey = new EncryptionKey("publicKey", "keyType");

            Assert.Throws<ArgumentNullException>(() => _encryptionFacade.EncryptData(null, hash, publicKey));
        }

        [Fact]
        public void DecryptData_ValidInput_ReturnsDecryptedData()
        {
            var encryptedData = Convert.ToBase64String(new byte[] { 1, 2, 3 });
            var encryptedHash = Convert.ToBase64String(new byte[] { 4, 5, 6 });
            var privateKey = new EncryptionKey("privateKey", "keyType");
            var decryptedData = "decrypted data";

            _mockEncryptionService
                .Setup(s => s.DecryptData(It.IsAny<byte[]>(), It.IsAny<byte[]>(), privateKey))
                .Returns(decryptedData);

            var result = _encryptionFacade.DecryptData(encryptedData, encryptedHash, privateKey);

            Assert.Equal(decryptedData, result);
        }

        [Fact]
        public void DecryptData_NullEncryptedData_ThrowsArgumentNullException()
        {
            var encryptedHash = Convert.ToBase64String(new byte[] { 4, 5, 6 });
            var privateKey = new EncryptionKey("privateKey", "keyType");

            Assert.Throws<ArgumentNullException>(() => _encryptionFacade.DecryptData(null, encryptedHash, privateKey));
        }

        [Fact]
        public void DecryptData_NullEncryptedHash_ThrowsArgumentNullException()
        {
            var encryptedData = Convert.ToBase64String(new byte[] { 1, 2, 3 });
            var privateKey = new EncryptionKey("privateKey", "keyType");

            Assert.Throws<ArgumentNullException>(() => _encryptionFacade.DecryptData(encryptedData, null, privateKey));
        }
    }
}