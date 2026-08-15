using System.Security.Cryptography;
using System.Text;
using Aegis.Contracts;
using Aegis.Core.Crypto;
using Aegis.Core.Helpers;

namespace Aegis.Core.FileEncryption;

internal sealed class FileEncryptionService
{
    private static readonly byte[] FileSignature =
        "v1.0"u8.ToArray();

    public async Task<FileOperationResult> EncryptAsync(
        string inputPath,
        ServerCryptoSession session,
        IProgress<double>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(inputPath))
            throw new ArgumentException("Invalid file path.");

        if (!File.Exists(inputPath))
            throw new FileNotFoundException(inputPath);

        var outputPath = Path.Combine(
            Path.GetTempPath(),
            $"{Guid.NewGuid():N}.encrypted");

        var fileKeySalt = RandomNumberGenerator.GetBytes(128);
        var layerSalts = SaltGenerator.CreateSalts();

        DerivedKeys? keys = null;

        try
        {
            await using var inputStream = new FileStream(
                inputPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                1024 * 1024,
                FileOptions.SequentialScan);

            // ================= HEADER CHECK =================
            if (inputStream.Length >= FileSignature.Length)
            {
                var header = new byte[FileSignature.Length];

                var bytesRead = await inputStream.ReadAsync(header);
                if (bytesRead != header.Length)
                    throw new IOException("Failed to read file header.");

                if (header.SequenceEqual(FileSignature))
                    throw new InvalidOperationException("File already encrypted.");

                inputStream.Position = 0;
            }

            using var fileKey =
                session.CreateFileKey(
                    fileKeySalt);

            keys =
                KeyDerivation.DeriveKeys(
                    fileKey,
                    layerSalts);

            await using var finalStream = new FileStream(
                outputPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                1024 * 1024,
                FileOptions.SequentialScan);

            // ================= HEADER =================
            var ext = Path.GetExtension(inputPath) ?? string.Empty;
            var extBytes = Encoding.UTF8.GetBytes(ext);

            if (extBytes.Length > 255)
                throw new InvalidOperationException("Extension too long.");

            await finalStream.WriteAsync(FileSignature);
            await finalStream.WriteAsync(fileKeySalt);

            foreach (var salt in layerSalts)
                await finalStream.WriteAsync(salt);

            await finalStream.WriteAsync(new[] { (byte)extBytes.Length });
            await finalStream.WriteAsync(extBytes);

            // ================= PIPELINE STREAM =================
            var options = new CryptoPipelineOptions
            {
                CancellationToken = CancellationToken.None // replace if you have real CTS
            };

            try
            {
                await CryptoAttackCampaign.Run(
                    keys,
                    options,
                    1024 * 1024 * 1024);
            }
            catch (Exception ex)
            {
                Console.WriteLine("===============================");
                Console.WriteLine("ATTACK FAILED");
                Console.WriteLine(ex);
                Console.WriteLine("===============================");
            }

            await finalStream.FlushAsync();

            Logging.Logging.Log("PIPELINE", "ENCRYPT COMPLETE");

            return new FileOperationResult
            {
                OutputPath = outputPath,
                IsEncrypted = true,
                SuggestedExtension = ".encrypted"
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKeySalt);

            foreach (var salt in layerSalts)
                CryptographicOperations.ZeroMemory(salt);

            keys?.Dispose();
        }
    }

    public async Task<FileOperationResult> DecryptAsync(
        string inputPath,
        ServerCryptoSession session,
        IProgress<double>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(inputPath))
            throw new ArgumentException(
                "Invalid file path.");

        if (!File.Exists(inputPath))
            throw new FileNotFoundException(
                inputPath);

        await using var input =
            new FileStream(
                inputPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                1024 * 1024,
                FileOptions.SequentialScan);

        Console.WriteLine($"Stream position before decrypt: {input.Position}");

        // ---- Verify signature ----
        var sig =
            await ReadExact.ReadExactAsync(
                input,
                FileSignature.Length);

        if (!sig.SequenceEqual(FileSignature))
            throw new CryptographicException(
                "Invalid file signature.");

        // ---- Read FileKeySalt ----
        var fileKeySalt =
            await ReadExact.ReadExactAsync(
                input,
                128);

        // Derive file key from authenticated session
        using var fileKey =
            session.CreateFileKey(fileKeySalt);

        // ---- Read crypto salts ----
        var cryptoSalts =
            new byte[9][];

        for (var i = 0; i < 9; i++)
            cryptoSalts[i] =
                await ReadExact.ReadExactAsync(
                    input,
                    128);

        // ---- Derive keys ----
        var keys =
            KeyDerivation.DeriveKeys(
                fileKey,
                cryptoSalts);

        try
        {
            // ---- Read extension ----
            var extLen = input.ReadByte();

            var extBytes =
                await ReadExact.ReadExactAsync(
                    input,
                    extLen);

            var originalExtension =
                Encoding.UTF8.GetString(extBytes);

            var outputPath =
                Path.Combine(
                    Path.GetTempPath(),
                    $"{Guid.NewGuid():N}{originalExtension}");

            await using var output =
                new FileStream(
                    outputPath,
                    FileMode.Create,
                    FileAccess.Write,
                    FileShare.None,
                    1024 * 1024);

            var options = new CryptoPipelineOptions();

            // ---- Decrypt payload ----
            await Methods.Decrypt(
                input,
                output,
                keys,
                options);

            await output.FlushAsync();

            return new FileOperationResult
            {
                OutputPath = outputPath,
                IsEncrypted = false,
                SuggestedExtension = originalExtension
            };
        }

        finally
        {
            CryptographicOperations.ZeroMemory(fileKeySalt);
            CryptographicOperations.ZeroMemory(cryptoSalts[0]);
            CryptographicOperations.ZeroMemory(cryptoSalts[1]);
            CryptographicOperations.ZeroMemory(cryptoSalts[2]);
            CryptographicOperations.ZeroMemory(cryptoSalts[3]);
            CryptographicOperations.ZeroMemory(cryptoSalts[4]);
            CryptographicOperations.ZeroMemory(cryptoSalts[5]);
            CryptographicOperations.ZeroMemory(cryptoSalts[6]);
            CryptographicOperations.ZeroMemory(cryptoSalts[7]);

            keys?.Dispose();
        }
    }
}