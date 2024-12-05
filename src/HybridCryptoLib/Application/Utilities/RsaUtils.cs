namespace HybridCryptoLib.Application.Utilities;

public class RsaUtils
{
    public static string ReadPublicKey(string filePath)
    {
        return File.ReadAllText(filePath);
    }

    public static string ReadPrivateKey(string filePath)
    {
        return File.ReadAllText(filePath);
    }
    
    public static byte[] ExtractPublicKeyFromPem(string pem)
    {
        var pemHeader = "-----BEGIN RSA PUBLIC KEY-----";
        var pemFooter = "-----END RSA PUBLIC KEY-----";

        var start = pem.IndexOf(pemHeader, StringComparison.Ordinal) + pemHeader.Length;
        var end = pem.IndexOf(pemFooter, start, StringComparison.Ordinal);

        var base64 = pem.Substring(start, end - start).Replace("\n", "").Replace("\r", "");
        return Convert.FromBase64String(base64);
    }
        
    public static byte[] ExtractPrivateKeyFromPem(string pem)
    {
        const string privateKeyHeader = "-----BEGIN PRIVATE KEY-----";
        const string privateKeyFooter = "-----END PRIVATE KEY-----";

        var start = pem.IndexOf(privateKeyHeader, StringComparison.Ordinal) + privateKeyHeader.Length;
        var end = pem.IndexOf(privateKeyFooter, start, StringComparison.Ordinal);
        var base64 = pem.Substring(start, end - start).Replace("\n", "").Replace("\r", "");

        return Convert.FromBase64String(base64);
    }
}