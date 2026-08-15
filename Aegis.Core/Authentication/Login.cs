using Aegis.Contracts;
using Aegis.Core.Crypto;
using Aegis.Core.Storage;
using Aegis.Core.Tpm;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Aegis.Core.Authentication
{
    internal static class Login
    {
        internal static async Task<PrimaryAuthenticationResult> LoginAccount(
     TpmSealService tpm,
     byte[] userPassword,
     KeyBlob blob,
     KeyStore store,
     string username)
        {
            var srk =
                tpm.CreateOrLoadSrk();

            // =========================================================
            // 1. PASSWORD FACTOR
            // =========================================================

            var accountArgonSettings =
                new CryptoSettings
                {
                    ArgonIterations =
                        blob.ArgonIterations,

                    ArgonMemoryKb =
                        blob.ArgonMemory,

                    ArgonParallelism =
                        blob.ArgonParallelism
                };

            if (blob.ArgonIterations <= 0 ||
                blob.ArgonIterations > 256)
            {
                throw new CryptographicException(
                    "Invalid Argon2 iteration count.");
            }

            if (blob.ArgonMemory < 1024 ||
                blob.ArgonMemory > 32 * 1024 * 1024)
            {
                throw new CryptographicException(
                    "Invalid Argon2 memory.");
            }

            if (blob.ArgonParallelism <= 0 ||
                blob.ArgonParallelism > 128)
            {
                throw new CryptographicException(
                    "Invalid Argon2 parallelism.");
            }

            byte[] passwordHash =
                await PasswordDerivation.Argon2Id(
                    userPassword,
                    blob.PasswordSalt,
                    32,
                    accountArgonSettings);

            byte[] passwordKEK =
                Hkdf.HkdfExpand(
                    passwordHash,
                    blob.PasswordHkdfSalt,
                    "PWD-KEK"u8,
                    32);

            CryptographicOperations.ZeroMemory(
                passwordHash);

            // =========================================================
            // 2. TPM FACTOR
            // =========================================================

            byte[] tpmSecret =
                tpm.Unseal(
                    blob,
                    srk);

            byte[] tpmKEK =
                Hkdf.HkdfExpand(
                    tpmSecret,
                    blob.TpmSalt,
                    "TPM-KEK"u8,
                    32);

            CryptographicOperations.ZeroMemory(
                tpmSecret);

            // =========================================================
            // 3. WINDOWS HELLO FACTOR
            // =========================================================

            var helloKey =
                WindowsHelloManager.GetOrCreateHelloKey(
                    blob.HelloKeyName);

            byte[] aad =
                Encoding.UTF8.GetBytes(
                    JsonSerializer.Serialize(
                        new
                        {
                            v = 1,
                            user = username,
                            key = blob.HelloKeyName,
                            type = "HELLO",
                            device = Environment.MachineName
                        }));

            byte[] helloSecret =
                WindowsHelloManager.Decrypt(
                    helloKey,
                    blob.HelloEncryptedKey,
                    aad);

            byte[] helloKEK =
                Hkdf.HkdfExpand(
                    helloSecret,
                    blob.HelloSalt,
                    "HELLO-KEK"u8,
                    32);

            CryptographicOperations.ZeroMemory(
                helloSecret);

            CryptographicOperations.ZeroMemory(
                aad);

            // =========================================================
            // 4. COMBINED KEK
            // =========================================================

            byte[] combined =
                new byte[96];

            byte[] combinedKEK;

            try
            {
                Buffer.BlockCopy(
                    passwordKEK,
                    0,
                    combined,
                    0,
                    32);

                Buffer.BlockCopy(
                    tpmKEK,
                    0,
                    combined,
                    32,
                    32);

                Buffer.BlockCopy(
                    helloKEK,
                    0,
                    combined,
                    64,
                    32);

                combinedKEK =
                    Hkdf.HkdfExpand(
                        combined,
                        blob.CombinedKdfSalt,
                        "MULTI-FACTOR-KEK"u8,
                        32);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    combined);

                CryptographicOperations.ZeroMemory(
                    passwordKEK);

                CryptographicOperations.ZeroMemory(
                    tpmKEK);

                CryptographicOperations.ZeroMemory(
                    helloKEK);
            }

            // =========================================================
            // 5. AUTHENTICATE KEYSTORE
            // =========================================================

            byte[] hmacKeyBytes =
                new byte[64];
            HmacKey hmacKey;

            try
            {
                using var aes =
                    new AesGcm(
                        combinedKEK,
                        16);

                aes.Decrypt(
                    blob.HmacKeyNonce,
                    blob.HmacKeyCipher,
                    blob.HmacKeyTag,
                    hmacKeyBytes);

                hmacKey =
                    new HmacKey(
                        hmacKeyBytes);
            }
            catch (CryptographicException)
            {
                CryptographicOperations.ZeroMemory(
                    hmacKeyBytes);

                CryptographicOperations.ZeroMemory(
                    combinedKEK);

                throw new SecurityException(
                    "Invalid credentials.");
            }

            // =========================================================
            // 6. STORAGE KEY
            // =========================================================

            byte[] storageKey =
                Hkdf.HkdfExpand(
                    combinedKEK,
                    blob.GcmSalt,
                    "STORAGE-KEY"u8,
                    32);

            byte[] decryptedBlob =
                new byte[
                    blob.EncryptedKeyHierarchy.Length];

            try
            {
                using var aes =
                    new AesGcm(
                        storageKey,
                        16);

                aes.Decrypt(
                    blob.GcmNonce,
                    blob.EncryptedKeyHierarchy,
                    blob.GcmTag,
                    decryptedBlob);
            }
            catch (CryptographicException)
            {
                throw new SecurityException(
                    "Invalid credentials.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    storageKey);
            }

            // =========================================================
            // 7. UNWRAP MASTER KEY CHAIN
            // =========================================================

            byte[] masterKey;

            using (
                var ms =
                    new MemoryStream(
                        decryptedBlob))
            using (
                var br =
                    new BinaryReader(
                        ms))
            {
                int wrappedL1Length =
                    br.ReadInt32();

                byte[] wrappedL1 =
                    br.ReadBytes(
                        wrappedL1Length);

                int wrappedL2Length =
                    br.ReadInt32();

                byte[] wrappedL2 =
                    br.ReadBytes(
                        wrappedL2Length);

                int wrappedMasterLength =
                    br.ReadInt32();

                byte[] wrappedMaster =
                    br.ReadBytes(
                        wrappedMasterLength);

                byte[] kekL2 =
                    KeyWrap.AesKeyUnwrap(
                        combinedKEK,
                        wrappedL1);

                try
                {
                    byte[] kekL1 =
                        KeyWrap.AesKeyUnwrap(
                            kekL2,
                            wrappedL2);

                    try
                    {
                        masterKey =
                            KeyWrap.AesKeyUnwrap(
                                kekL1,
                                wrappedMaster);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(
                            kekL1);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        kekL2);
                }
            }

            CryptographicOperations.ZeroMemory(
                decryptedBlob);

            // =========================================================
            // 8. CREATE SECURE MASTER OWNER
            // =========================================================

            using var secureMaster =
                new SecureMasterKey(
                    masterKey);

            var accountRoot =
                SessionKeyFactory.CreateAccountRootKey(
                    secureMaster,
                    blob.SessionSalt);

            var fileRoot =
                SessionKeyFactory.CreateFileRootKey(
                    accountRoot,
                    blob.FileRootSalt);

            var memoryKey =
                SessionKeyFactory.CreateMemoryProtectionKey(
                    accountRoot,
                    blob.MemorySalt);

            var ipcWrapKey =
                SessionKeyFactory.CreateIpcWrappingKey(
                    accountRoot,
                    blob.IpcSalt);

            // =========================================================
            // 11. CLEANUP COMBINED KEK
            // =========================================================

            CryptographicOperations.ZeroMemory(
                combinedKEK);

            // =========================================================
            // 12. CREATE SERVER CRYPTO SESSION
            // =========================================================

            return new PrimaryAuthenticationResult
            {
                AccountRootKey = accountRoot,

                FileRootKey = fileRoot,

                MemoryProtectionKey = memoryKey,

                IpcWrappingKey = ipcWrapKey,

                HmacKey = hmacKey
            };
        }
    }
}
