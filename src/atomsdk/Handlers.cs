using System.IO.Compression;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Core;

namespace Atomsdk;

public static class Handlers
{
    [SupportedOSPlatform("windows")]
    public static void TryGenerateKeys(string? password, string? moveOld, FileInfo? outputPublicKey, bool ignoreMoveOld)
    {
        if (outputPublicKey == null) return;
        if (moveOld == null && !ignoreMoveOld)
        {
            Console.WriteLine("Ignoring option to backup old PrivateKey will lead to loss of PrivateKey for" +
                              " previous version. To continue this operation, use --ignore-move-old, or add previous " +
                              "version for backup with -m [version].");
            return;
        }

        string privateKeyMovedTo;
        try
        {
            privateKeyMovedTo = Crypto.SetupKeysForRelease(password, moveOld!, outputPublicKey.FullName);
        }
        catch (FileErrorException e)
        {
            Console.WriteLine("Error backing up old key. File already exists. \n\n" + e.Message);
            return;
        }

        Console.WriteLine("Generated new pair. New PrivateKey is now current. ");
        var passwordSet = password == null ? "not " : "";
        Console.WriteLine($"Password was {passwordSet}set. ");
        if(privateKeyMovedTo != "")
            Console.WriteLine($"Old private key moved as {privateKeyMovedTo}");
        Console.WriteLine($"New PublicKey written to {outputPublicKey.FullName}");
    }

    [SupportedOSPlatform("windows")]
    public static void TrySign(FileInfo? input, FileInfo? output, string? customPrivateKeyPath, string? password)
    {
        if(input == null || output == null) 
            return;
        var tempPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AtomAppManager",
            "temp");
        var payloadPath = Path.Combine(tempPath, "payload.zip");
        var signPath = Path.Combine(tempPath, "signature.sig");
        Directory.CreateDirectory(tempPath);
        
        File.Copy(input.FullName, payloadPath, true);
        try
        {
            if(customPrivateKeyPath != null)
                Console.WriteLine($"Using custom Pk (ver {customPrivateKeyPath})");
            var sign = Crypto.SignData(password, File.ReadAllBytes(payloadPath), customPrivateKeyPath);
            File.WriteAllBytes(signPath, sign);
        }
        catch (CryptographicException e)
        {
            Console.WriteLine("Error decrypting current PrivateKey. Check your password. You may need to regenerate " +
                              "your keypair to sign files.\n\n" + e.Message);
            return;
        }
        
        if (File.Exists(output.FullName))
        {
            var suffix = "";
            if(File.Exists(output.FullName + ".backup"))
            {
                var i = 1;

                while(File.Exists(output.FullName + ".backup-" + i))
                {
                    i += 1;
                }
                
                suffix = "-" + i;
            }

            var dest = output.FullName + ".backup" + suffix;
            Console.WriteLine($"Moving {output.FullName} to {dest}");
            File.Move(output.FullName, dest);    
        }
        
        ZipFile.CreateFromDirectory(tempPath, output.FullName);
        Console.WriteLine($"Signed: {output.FullName} ({new FileInfo(output.FullName).Length} bytes)");
        
        Directory.Delete(tempPath, true);
    }
    
    public static void TryVerifyData(FileInfo? publicKeyPath, FileInfo? archivePath)
    {
        if (archivePath == null || publicKeyPath == null) return;
        var tempPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AtomAppManager",
            "temp");
        var payloadPath = Path.Combine(tempPath, "payload.zip");
        var signPath = Path.Combine(tempPath, "signature.sig");
        Directory.Delete(tempPath, true);
        ZipFile.ExtractToDirectory(archivePath.FullName, tempPath);
        if(!(File.Exists(signPath) && File.Exists(payloadPath)))
            throw new FileErrorException("This archive was not signed with atomsdk.");
        var result = Crypto.VerifyData(File.ReadAllBytes(payloadPath), File.ReadAllBytes(signPath), 
            File.ReadAllBytes(publicKeyPath.FullName));
        Console.WriteLine(result ? "Signature verified." : "Signature verification failed.");
    }
}