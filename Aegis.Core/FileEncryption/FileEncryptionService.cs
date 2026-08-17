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
     FileKey fileKey,
     byte[] fileKeySalt,
     string username,
     string sessionId,
     IProgress<double>? progress = null,
     CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            inputPath);

        ArgumentNullException.ThrowIfNull(
            fileKey);

        ArgumentNullException.ThrowIfNull(
            fileKeySalt);

        ArgumentException.ThrowIfNullOrWhiteSpace(
            username);

        if (!File.Exists(inputPath))
        {
            throw new FileNotFoundException(
                inputPath);
        }

        if (fileKeySalt.Length != 128)
        {
            throw new ArgumentException(
                "File key salt must be exactly 128 bytes.",
                nameof(fileKeySalt));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var outputPath =
            Path.Combine(
                Path.GetTempPath(),
                $"{Guid.NewGuid():N}.encrypted");

        var layerSalts =
            SaltGenerator.CreateSalts();

        DerivedKeys? keys = null;

        bool success = false;

        try
        {
            await using var inputStream =
                new FileStream(
                    inputPath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    1024 * 1024,
                    FileOptions.SequentialScan);

            // ========================================================
            // CHECK WHETHER INPUT IS ALREADY ENCRYPTED
            // ========================================================

            if (inputStream.Length >= FileSignature.Length)
            {
                var header =
                    new byte[FileSignature.Length];

                try
                {
                    var bytesRead =
                        await inputStream.ReadAsync(
                            header,
                            cancellationToken);

                    if (bytesRead != header.Length)
                    {
                        throw new IOException(
                            "Failed to read file header.");
                    }

                    if (CryptographicOperations.FixedTimeEquals(
                            header,
                            FileSignature))
                    {
                        throw new InvalidOperationException(
                            "File is already encrypted.");
                    }

                    inputStream.Position = 0;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        header);
                }
            }

            // ========================================================
            // DERIVE PIPELINE KEYS
            // ========================================================

            keys =
                KeyDerivation.DeriveKeys(
                    fileKey,
                    layerSalts);

            // ========================================================
            // CREATE OUTPUT
            // ========================================================

            await using var finalStream =
                new FileStream(
                    outputPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    1024 * 1024,
                    FileOptions.SequentialScan);

            // ========================================================
            // ORIGINAL FILE EXTENSION
            // ========================================================

            var extension =
                Path.GetExtension(inputPath)
                ?? string.Empty;

            var extensionBytes =
                Encoding.UTF8.GetBytes(
                    extension);

            if (extensionBytes.Length > 255)
            {
                throw new InvalidOperationException(
                    "Extension is too long.");
            }

            // ========================================================
            // WRITE HEADER
            // ========================================================

            await finalStream.WriteAsync(
                FileSignature,
                cancellationToken);

            await finalStream.WriteAsync(
                fileKeySalt,
                cancellationToken);

            foreach (var salt in layerSalts)
            {
                await finalStream.WriteAsync(
                    salt,
                    cancellationToken);
            }

            await finalStream.WriteAsync(
                new[] { (byte)extensionBytes.Length },
                cancellationToken);

            await finalStream.WriteAsync(
                extensionBytes,
                cancellationToken);

            // ========================================================
            // ENCRYPTION PIPELINE
            // ========================================================

            var options =
                new CryptoPipelineOptions
                {
                    CancellationToken =
                        cancellationToken
                };

            try
            {
                await Methods.Encrypt(
                    inputStream,
                    finalStream,
                    keys,
                    options);
            }
            catch (OperationCanceledException ex)
            {
                Logging.ExceptionLogger.Log(
                    ex,
                    "File encryption cancelled.",
                    username);

                throw;
            }
            catch (CryptographicException ex)
            {
                Logging.ExceptionLogger.Log(
                    ex,
                    "File encryption cryptographic failure.",
                    username);

                throw;
            }
            catch (IOException ex)
            {
                Logging.ExceptionLogger.Log(
                    ex,
                    "File encryption I/O failure.",
                    username);

                throw;
            }
            catch (Exception ex)
            {
                Logging.ExceptionLogger.Log(
                    ex,
                    "File encryption failed unexpectedly.",
                    username);

                throw;
            }

            await finalStream.FlushAsync(
                cancellationToken);

            success = true;

            Logging.Logging.Log(
                "PIPELINE",
                "ENCRYPT COMPLETE");

            return new FileOperationResult
            {
                OutputPath =
                    outputPath,

                IsEncrypted =
                    true,

                SuggestedExtension =
                    ".encrypted"
            };
        }
        finally
        {
            foreach (var salt in layerSalts)
            {
                CryptographicOperations.ZeroMemory(
                    salt);
            }

            keys?.Dispose();

            // Never leave a partial encrypted file behind.
            if (!success &&
                File.Exists(outputPath))
            {
                try
                {
                    File.Delete(
                        outputPath);
                }
                catch
                {
                    // Cleanup must never hide
                    // the original exception.
                }
            }
        }
    }

    public async Task<FileOperationResult> DecryptAsync(
    string inputPath,
    Func<byte[], FileKey> createFileKey,
    string username,
    IProgress<double>? progress = null,
    CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            inputPath);

        ArgumentNullException.ThrowIfNull(
            createFileKey);

        ArgumentException.ThrowIfNullOrWhiteSpace(
            username);

        if (!File.Exists(inputPath))
        {
            throw new FileNotFoundException(
                inputPath);
        }

        cancellationToken.ThrowIfCancellationRequested();

        await using var input =
            new FileStream(
                inputPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                1024 * 1024,
                FileOptions.SequentialScan);

        // ============================================================
        // SIGNATURE
        // ============================================================

        var signature =
            await ReadExact.ReadExactAsync(
                input,
                FileSignature.Length,
                ct: cancellationToken);

        if (!CryptographicOperations.FixedTimeEquals(
                signature,
                FileSignature))
        {
            throw new CryptographicException(
                "Invalid file signature.");
        }

        // ============================================================
        // FILE KEY SALT
        // ============================================================

        var fileKeySalt =
            await ReadExact.ReadExactAsync(
                input,
                128,
                ct: cancellationToken);

        // ============================================================
        // PIPELINE SALTS
        // ============================================================

        var cryptoSalts =
            new byte[9][];

        DerivedKeys? keys = null;

        FileKey? fileKey = null;

        string? outputPath = null;

        bool success = false;

        try
        {
            // ========================================================
            // READ PIPELINE SALTS
            // ========================================================

            for (var i = 0;
                 i < cryptoSalts.Length;
                 i++)
            {
                cryptoSalts[i] =
                    await ReadExact.ReadExactAsync(
                        input,
                        128,
                        ct: cancellationToken);
            }

            // ========================================================
            // RECREATE FILE KEY
            // ========================================================

            fileKey =
                createFileKey(fileKeySalt);

            // ========================================================
            // DERIVE PIPELINE KEYS
            // ========================================================

            keys =
                KeyDerivation.DeriveKeys(
                    fileKey,
                    cryptoSalts);

            // ========================================================
            // READ ORIGINAL EXTENSION LENGTH
            // ========================================================

            var extensionLength =
                input.ReadByte();

            if (extensionLength < 0)
            {
                throw new CryptographicException(
                    "Encrypted file is truncated.");
            }

            if (extensionLength > 255)
            {
                throw new CryptographicException(
                    "Invalid extension length.");
            }

            // ========================================================
            // READ ORIGINAL EXTENSION
            // ========================================================

            var extensionBytes =
                await ReadExact.ReadExactAsync(
                    input,
                    extensionLength,
                    ct: cancellationToken);

            var originalExtension =
                Encoding.UTF8.GetString(
                    extensionBytes);

            // ========================================================
            // VALIDATE EXTENSION
            // ========================================================

            if (originalExtension.Length > 0)
            {
                if (!originalExtension.StartsWith(
                        ".",
                        StringComparison.Ordinal))
                {
                    throw new CryptographicException(
                        "Invalid original file extension.");
                }

                if (originalExtension.IndexOfAny(
                        Path.GetInvalidFileNameChars()) >= 0)
                {
                    throw new CryptographicException(
                        "Invalid characters in original file extension.");
                }
            }

            // ========================================================
            // CREATE TEMPORARY PLAINTEXT OUTPUT
            // ========================================================

            outputPath =
                Path.Combine(
                    Path.GetTempPath(),
                    $"{Guid.NewGuid():N}{originalExtension}");

            await using var output =
                new FileStream(
                    outputPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    1024 * 1024,
                    FileOptions.SequentialScan);

            // ========================================================
            // DECRYPTION PIPELINE
            // ========================================================

            var options =
                new CryptoPipelineOptions
                {
                    CancellationToken =
                        cancellationToken
                };

            try
            {
                await Methods.Decrypt(
                    input,
                    output,
                    keys,
                    options);
            }
            catch (OperationCanceledException ex)
            {
                Logging.ExceptionLogger.Log(
                    ex,
                    "File decryption cancelled.",
                    username);

                throw;
            }
            catch (CryptographicException ex)
            {
                Logging.ExceptionLogger.Log(
                    ex,
                    "File decryption cryptographic failure.",
                    username);

                throw;
            }
            catch (IOException ex)
            {
                Logging.ExceptionLogger.Log(
                    ex,
                    "File decryption I/O failure.",
                    username);

                throw;
            }
            catch (Exception ex)
            {
                Logging.ExceptionLogger.Log(
                    ex,
                    "File decryption failed unexpectedly.",
                    username);

                throw;
            }

            await output.FlushAsync(
                cancellationToken);

            success = true;

            Logging.Logging.Log(
                "PIPELINE",
                "DECRYPT COMPLETE");

            return new FileOperationResult
            {
                OutputPath =
                    outputPath,

                IsEncrypted =
                    false,

                SuggestedExtension =
                    originalExtension
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(
                fileKeySalt);

            foreach (var salt in cryptoSalts)
            {
                if (salt != null)
                {
                    CryptographicOperations.ZeroMemory(
                        salt);
                }
            }

            keys?.Dispose();

            fileKey?.Dispose();

            // ========================================================
            // DESTROY PARTIAL PLAINTEXT ON FAILURE
            // ========================================================

            if (!success &&
                outputPath != null &&
                File.Exists(outputPath))
            {
                try
                {
                    await IO.FileEraser.SecureDeleteAsync(
                            outputPath, cancellationToken);
                }
                catch
                {
                    // Never hide the original
                    // cryptographic/I/O exception.
                }
            }
        }
    }
}