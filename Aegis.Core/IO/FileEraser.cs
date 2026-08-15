using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Aegis.Core.Logging;

namespace Aegis.Core.IO
{
    internal static class FileEraser
    {
        public static async Task SecureDeleteAsync(
    string path,
    CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(path))
                return;

            if (!File.Exists(path))
                return;

            string journal = path + ".deljournal";
            string tempEnc = path + ".enc.tmp";

            byte[] key = null;

            try
            {
                Logging.Logging.Log("SECDEL", $"START path={path}");

                // =========================
                // 1. WRITE JOURNAL (CRASH SAFETY)
                // =========================
                await File.WriteAllTextAsync(journal, "IN_PROGRESS", ct);
                await using (var fs = new FileStream(journal, FileMode.Open, FileAccess.Write, FileShare.None))
                {
                    await fs.FlushAsync(ct);
                    ForceFlushToDisk(fs);
                }

                // =========================
                // 2. GENERATE KEY
                // =========================
                key = RandomNumberGenerator.GetBytes(32);

                // =========================
                // 3. NORMALIZE METADATA (REDUCE FORENSIC SIGNAL)
                // =========================
                var now = DateTime.UtcNow;

                File.SetCreationTime(path, now);
                File.SetLastAccessTime(path, now);
                File.SetLastWriteTime(path, now);

                // =========================
                // 4. ENCRYPT FILE → TEMP (NO PLAINTEXT LEFT BEHIND)
                // =========================
                await EncryptFileStreamAsync(path, tempEnc, key, ct);

                // =========================
                // 5. DELETE ORIGINAL FILE
                // =========================
                TryDelete(path);

                // =========================
                // 6. FINALIZE JOURNAL
                // =========================
                await File.WriteAllTextAsync(journal, "COMPLETE", ct);

                Logging.Logging.Log("SECDEL", $"COMPLETE path={path}");
            }
            catch (Exception ex)
            {
                Logging.Logging.Log("SECDEL", $"ERROR: {ex}");

                TryDelete(tempEnc);
            }
            finally
            {
                // =========================
                // 7. CRYPTO KEY DISPOSAL (IMPORTANT)
                // =========================
                if (key != null)
                {
                    CryptographicOperations.ZeroMemory(key);
                }

                // =========================
                // 8. CLEANUP JOURNAL (BEST EFFORT)
                // =========================
                TryDelete(journal);
            }
        }

        private static async Task EncryptFileStreamAsync(
            string inputPath,
            string outputPath,
            byte[] key,
            CancellationToken ct)
        {
            await using var input = new FileStream(
                inputPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                1024 * 1024,
                FileOptions.SequentialScan);

            await using var output = new FileStream(
                outputPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                1024 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            byte[] iv = RandomNumberGenerator.GetBytes(16);

            await output.WriteAsync(iv, ct);

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            await using var crypto = new CryptoStream(
                output,
                aes.CreateEncryptor(),
                CryptoStreamMode.Write);

            byte[] buffer = ArrayPool<byte>.Shared.Rent(1024 * 1024);

            try
            {
                int read;

                while ((read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), ct)) > 0)
                {
                    await crypto.WriteAsync(buffer.AsMemory(0, read), ct);

                    // 🔥 periodic flush (important for crash safety)
                    await crypto.FlushAsync(ct);

                    ForceFlushToDisk(output);
                }

                await crypto.FlushFinalBlockAsync(ct);

                ForceFlushToDisk(output);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private static void TryDelete(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
                return;

            try
            {
                if (!File.Exists(path))
                    return;

                // best-effort remove read-only flags (common failure cause)
                var attr = File.GetAttributes(path);

                if ((attr & FileAttributes.ReadOnly) != 0)
                    File.SetAttributes(path, attr & ~FileAttributes.ReadOnly);

                File.Delete(path);

                Logging.Logging.Log("SECDEL", $"Deleted: {path}");
            }
            catch (Exception ex)
            {
                Logging.Logging.Log("SECDEL", $"Delete failed: {path} :: {ex.Message}");
            }
        }

        private static void ForceFlushToDisk(FileStream fs)
        {
            try
            {
                // .NET flush
                fs.Flush(true);

                // OS-level flush
                FlushFileBuffers(fs.SafeFileHandle.DangerousGetHandle());
            }
            catch (Exception ex)
            {
                Logging.Logging.Log("FLUSH", $"Flush failed: {ex.Message}");
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FlushFileBuffers(IntPtr hFile);
    }
}
