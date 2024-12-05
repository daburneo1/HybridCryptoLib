﻿namespace HybridCryptoLib.Application.interfaces
{
    public interface IEncryptionService
    {
        (byte[] EncryptedData, byte[] EncryptedHash) EncryptData(string plainText, string hash, string publicKey);
        string DecryptData(string encryptedData, string encryptedHash, string privateKey);
    }
}