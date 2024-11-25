namespace HybridCryptoLib.Application.Utilities;

public class RsaKeyReader
{
    public static string ReadPublicKey(string filePath)
    {
        return File.ReadAllText(filePath);
    }

    public static string ReadPrivateKey(string filePath)
    {
        return File.ReadAllText(filePath);
    }
}