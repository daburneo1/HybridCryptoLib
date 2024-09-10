using System.Text;
using Application.interfaces;
using Domain;
using Moq;
using WebAPI;
using Xunit;

namespace Tests
{
    public class EncryptionFacadeTests
    {
        [Fact]
        public void EncryptData_ReturnsEncryptedString_WhenValidInput()
        {
            // Arrange
            var encryptionServiceMock = new Mock<IEncryptionService>();
            var encryptionFacade = new EncryptionFacade(encryptionServiceMock.Object);
            var data = Encoding.UTF8.GetBytes("test data");
            var publicKey = new EncryptionKey("publicKey");
            var expectedEncryptedData = Convert.ToBase64String(new byte[] { 1, 2, 3 });

            encryptionServiceMock.Setup(es => es.EncryptData(data, publicKey)).Returns(Convert.FromBase64String(expectedEncryptedData));

            // Act
            var result = encryptionFacade.EncryptData(data, publicKey);

            // Assert
            Assert.Equal(expectedEncryptedData, result);
        }

        [Fact]
        public void DecryptData_ReturnsDecryptedData_WhenValidInput()
        {
            // Arrange
            var encryptionServiceMock = new Mock<IEncryptionService>();
            var encryptionFacade = new EncryptionFacade(encryptionServiceMock.Object);
            var encryptedData = Convert.ToBase64String(new byte[] { 1, 2, 3 });
            var privateKey = new EncryptionKey("privateKey");
            var expectedDecryptedData = Encoding.UTF8.GetBytes("test data");

            encryptionServiceMock.Setup(es => es.DecryptData(It.IsAny<EncryptedData>(), privateKey)).Returns(expectedDecryptedData);

            // Act
            var result = encryptionFacade.DecryptData(encryptedData, privateKey);

            // Assert
            Assert.Equal(expectedDecryptedData, result);
        }

        [Fact]
        public void EncryptData_ThrowsException_WhenNullData()
        {
            // Arrange
            var encryptionServiceMock = new Mock<IEncryptionService>();
            var encryptionFacade = new EncryptionFacade(encryptionServiceMock.Object);
            byte[] data = null;
            var publicKey = new EncryptionKey("publicKey");

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => encryptionFacade.EncryptData(data, publicKey));
        }

        [Fact]
        public void DecryptData_ThrowsException_WhenNullEncryptedData()
        {
            // Arrange
            var encryptionServiceMock = new Mock<IEncryptionService>();
            var encryptionFacade = new EncryptionFacade(encryptionServiceMock.Object);
            string encryptedData = null;
            var privateKey = new EncryptionKey("privateKey");

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => encryptionFacade.DecryptData(encryptedData, privateKey));
        }

        [Fact]
        public void DecryptData_ReturnsOriginalData_WhenDataIsNotEncrypted()
        {
            // Arrange
            var encryptionServiceMock = new Mock<IEncryptionService>();
            var encryptionFacade = new EncryptionFacade(encryptionServiceMock.Object);
            var nonEncryptedData = "non-encrypted data";
            var privateKey = new EncryptionKey("privateKey");
            var expectedData = Encoding.UTF8.GetBytes(nonEncryptedData);

            encryptionServiceMock.Setup(es => es.DecryptData(It.IsAny<EncryptedData>(), privateKey)).Returns(expectedData);

            // Act
            var result = encryptionFacade.DecryptData(nonEncryptedData, privateKey);

            // Assert
            Assert.Equal(expectedData, result);
        }
    }
}