using System.Runtime.Versioning;
using Core;

namespace Atomsdk;
using System.CommandLine;

public class Atomsdk
{
    [SupportedOSPlatform("windows")]
    private static int Main(string[] args)
    {
        Option<string> passwordOption = new("--password", "-p")
        {
            Description = "Password to encrypt or decrypt your private key. Store it safely. Your private key is the " +
                          "only way to sign your packages and repositories as developer.",
            Required = true
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
        
        RootCommand rootCommand = new("AtomAppManager Developer SDK");

        Command generateKeysCommand = new("generatekeys", "Generate new pair (PrivateKey, PublicKey)" +
                                                          " for new release.")
        {
            passwordOption,
            moveOldOption,
            outputPublicKeyOption,
            ignoreMoveOldOption
        };
        
        rootCommand.Subcommands.Add(generateKeysCommand);
        
        generateKeysCommand.SetAction(result => TryGenerateKeys(result.GetValue(passwordOption), 
            result.GetValue(moveOldOption), 
            result.GetValue(outputPublicKeyOption),
            result.GetValue(ignoreMoveOldOption)));

        return rootCommand.Parse(args).Invoke();
    }

    [SupportedOSPlatform("windows")]
    private static void TryGenerateKeys(string? password, string? moveOld, FileInfo? outputPublicKey, bool ignoreMoveOld)
    {
        if (password == null || outputPublicKey == null) return;
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
            privateKeyMovedTo = Crypto.SetupKeysForRelease(password, moveOld ?? "", outputPublicKey.FullName);
        }
        catch (FileErrorException e)
        {
            Console.WriteLine("Error backing up old key. File already exists. \n\n" + e.Message);
            return;
        }

        Console.WriteLine("Generated new pair. New PrivateKey is now current. ");
        if(privateKeyMovedTo != "")
            Console.WriteLine($"Old private key moved as {privateKeyMovedTo}");
        Console.WriteLine($"New PublicKey written to {outputPublicKey.FullName}");
    }
}