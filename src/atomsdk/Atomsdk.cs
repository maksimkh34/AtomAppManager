using System.Runtime.Versioning;

namespace Atomsdk;
using System.CommandLine;

public static class Atomsdk
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
        
        generateKeysCommand.SetAction(result => Handlers.TryGenerateKeys(result.GetValue(encryptingPasswordOption), 
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
        Option<string> customPrivateKeyPath = new("--private-key", "-pk")
        {
            Description = "custom version of private key (stored with generatekeys -m version)"
        };
        
        Command signCommand = new("sign", "Sign payload zip")
        {
            inputPayloadPath,
            outputFilePath,
            encryptingPasswordOption,
            customPrivateKeyPath
        };
        
        rootCommand.Subcommands.Add(signCommand);
        
        signCommand.SetAction(result => Handlers.TrySign(result.GetValue(inputPayloadPath), 
            result.GetValue(outputFilePath),
            result.GetValue(customPrivateKeyPath),
            result.GetValue(encryptingPasswordOption)));

        return rootCommand.Parse(args).Invoke();
    }
}