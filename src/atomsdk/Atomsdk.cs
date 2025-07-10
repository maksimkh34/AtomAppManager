using System.IO.Compression;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Core;

namespace Atomsdk;
using System.CommandLine;

public class Atomsdk
{
    [SupportedOSPlatform("windows")]
    private static int Main(string[] args)
    {
        RootCommand rootCommand = new("AtomAppManager Developer SDK");
        
        // generatekeys
        
        Option<string> encryptingPasswordOption = new("--password", "-p")
        {
            Description = "Password to encrypt or decrypt your private key. Store it safely. Your private key is the " +
                          "only way to sign your packages and repositories as developer."
        };
        Option<FileInfo> outputPublicKeyOption = new("--output", "-o")
        {
            Description = "Output file for PublicKey. Upload it to your repository (release.pub if latest, " +
                          "version_name.pub if archived",
            Required = true
        };
        Option<string> moveOldOption = new("--move-old", "-m")
        {
            Description = "Version of previous release. Moving old private key to \"[version].bin\" to archive your" +
                          " PrivateKey. Ignoring this option will lead to permanent loss of PrivateKey for previous version."
        };
        Option<bool> ignoreMoveOldOption = new("--ignore-move-old")
        {
            Description = "Ignore moveOldOption warning. You will permanently lose your current PrivateKey."
        };
        Command generateKeysCommand = new("generatekeys", "Generate new pair (PrivateKey, PublicKey)" +
                                                          " for new release.")
        {
            encryptingPasswordOption,
            moveOldOption,
            outputPublicKeyOption,
            ignoreMoveOldOption
        };
        
        rootCommand.Subcommands.Add(generateKeysCommand);
        
        generateKeysCommand.SetAction(result => TryGenerateKeys(result.GetValue(encryptingPasswordOption), 
            result.GetValue(moveOldOption), 
            result.GetValue(outputPublicKeyOption),
            result.GetValue(ignoreMoveOldOption)));
        
        // sign
        
        Option<FileInfo> inputPayloadPath = new("--input", "-i")
        {
            Description = "Input file for signing",
            Required = true
        };
        Option<FileInfo> outputFilePath = new("--output", "-o")
        {
            Description = "Output archive with signature.sig and payload.zip",
            Required = true
        };
        
        Command signCommand = new("sign", "Sign payload zip")
        {
            inputPayloadPath,
            outputFilePath,
            encryptingPasswordOption
        };
        
        rootCommand.Subcommands.Add(signCommand);
        
        signCommand.SetAction(result => TrySign(result.GetValue(inputPayloadPath), 
            result.GetValue(outputFilePath),
            result.GetValue(encryptingPasswordOption)));

        return rootCommand.Parse(args).Invoke();
    }

    [SupportedOSPlatform("windows")]
    private static void TryGenerateKeys(string? password, string? moveOld, FileInfo? outputPublicKey, bool ignoreMoveOld)
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
    private static void TrySign(FileInfo? input, FileInfo? output, string? password)
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
            var sign = Crypto.SignData(password, File.ReadAllBytes(payloadPath));
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
}