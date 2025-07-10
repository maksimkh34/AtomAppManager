using System.IO.Compression;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace Core;

public static class Crypto
{
    private static readonly string KeyStorageDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AtomAppManager", "keys");

    public const string CurrentPrivateKeyFilename = "current";

    private static readonly SignatureAlgorithm Algorithm = SignatureAlgorithm.Ed25519;
    
    private static string GetKeyPath(string name) => Path.Combine(KeyStorageDir, $"{name}.bin");
    
    public static (byte[], byte[]) GenerateKeyPair()
    {
        Directory.CreateDirectory(KeyStorageDir);

        using var key = new Key(Algorithm, new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        });

        var rawPrivate = key.Export(KeyBlobFormat.RawPrivateKey);
        var rawPublic = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

        return (rawPrivate, rawPublic);
    }

    [SupportedOSPlatform("windows")]
    private static void WriteEncryptedPrivateKey(string filename, byte[] privateKey, string? password)
    {
        byte[]? pass = null;
        if (password != null)
            pass = Encoding.UTF8.GetBytes(password);
        var protectedPrivate = ProtectedData.Protect(privateKey, pass, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(GetKeyPath(filename), protectedPrivate);
    }

    private static string MoveCurrentKeyTo(string version)
    {
        if (version == "")
            return "";
        if(File.Exists(GetKeyPath(version))) 
            throw new FileErrorException("PrivateKey file for this version already exists");
        if(!File.Exists(GetKeyPath(CurrentPrivateKeyFilename)))
            return "";
        File.Move(GetKeyPath(CurrentPrivateKeyFilename), GetKeyPath(version));
        return version;
    }

    [SupportedOSPlatform("windows")]
    public static string SetupKeysForRelease(string? password, string oldVersionName, string publicKeyFilePath)
    {
        var keys = GenerateKeyPair();
        var result = MoveCurrentKeyTo(oldVersionName);
        WriteEncryptedPrivateKey(CurrentPrivateKeyFilename, keys.Item1, password);
        WritePublicKey(keys.Item2, publicKeyFilePath);
        return result;
    }

    private static void WritePublicKey(byte[] publicKey, string filename)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(filename)!);
        File.WriteAllBytes(filename, publicKey);
    }
    
    [SupportedOSPlatform("windows")]
    public static byte[] SignData(string? password, byte[] payloadZip, string? customPrivateKeyPath = null)
    {
        byte[]? pass = null;
        if(password != null)
            pass = Encoding.UTF8.GetBytes(password);
        var privateKeyBytes = File.ReadAllBytes(GetKeyPath(customPrivateKeyPath ?? CurrentPrivateKeyFilename));
        var rawPrivate = ProtectedData.Unprotect(privateKeyBytes, pass
            , DataProtectionScope.CurrentUser);

        using var key = Key.Import(Algorithm, rawPrivate, KeyBlobFormat.RawPrivateKey);
        var hash = SHA256.HashData(payloadZip);

        return Algorithm.Sign(key, hash);
    }

    public static bool VerifyData(byte[] payloadZipBytes, byte[] signature, byte[] publicKey)
    {
        var pubKey = PublicKey.Import(Algorithm, publicKey, KeyBlobFormat.RawPublicKey);
        var hash = SHA256.HashData(payloadZipBytes);
        return Algorithm.Verify(pubKey, hash, signature);
    }
}