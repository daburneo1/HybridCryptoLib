namespace HybridCryptoLib.Domain
{
    public class EncryptedData
    {
        public string Data { get; set; } = string.Empty;
        public bool IsEncrypted { get; set; }

        public EncryptedData() { }

        public EncryptedData(string data, bool isEncrypted)
        {
            Data = data;
            IsEncrypted = isEncrypted;
        }

        public byte[] GetDataBytes()
        {
            return Convert.FromBase64String(Data);
        }
    }
}