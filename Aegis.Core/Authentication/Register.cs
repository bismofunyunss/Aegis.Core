using Aegis.Core.Crypto;
using Aegis.Core.Tpm;
using Aegis.Contracts;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Aegis.Core.Authentication
{
    internal sealed class Register
    {
        internal static async Task<RegistrationResult> RegisterAccount(
       TpmSealService tpm,
       byte[] userPassword,
       uint[] pcrs,
       string username,
       CryptoSettings cryptoConfig)
        {

            var srk = tpm.CreateOrLoadSrk();

            // =========================================================
            // 1. ROOT MASTER KEY (final secret we protect)
            // =========================================================
            byte[] masterKey = RandomNumberGenerator.GetBytes(64);

            // =========================================================
            // 2. PASSWORD FACTOR
            // =========================================================
            byte[] passwordSalt = RandomNumberGenerator.GetBytes(128);

            byte[] passwordHash =
                await PasswordDerivation.Argon2Id(
                    userPassword,
                    passwordSalt,
                    32,
                    cryptoConfig);

            byte[] passwordHkdfSalt = RandomNumberGenerator.GetBytes(128);

            byte[] passwordKEK =
                Hkdf.HkdfExpand(
                    passwordHash,
                    passwordHkdfSalt,
                    "PWD-KEK"u8,
                    32);

            CryptographicOperations.ZeroMemory(passwordHash);

            // =========================================================
            // 3. TPM FACTOR
            // =========================================================
            byte[] tpmSecret = RandomNumberGenerator.GetBytes(32);

            var sealedBlob = tpm.Seal(tpmSecret, srk);

            byte[] tpmSalt = RandomNumberGenerator.GetBytes(128);

            byte[] tpmKEK =
                Hkdf.HkdfExpand(
                    tpmSecret,
                    tpmSalt,
                    "TPM-KEK"u8,
                    32);

            CryptographicOperations.ZeroMemory(tpmSecret);

            // =========================================================
            // 4. WINDOWS HELLO FACTOR
            // =========================================================
            string helloKeyName = $"Hello-{username}";
            var helloKey = WindowsHelloManager.GetOrCreateHelloKey(helloKeyName);

            byte[] helloSecret = RandomNumberGenerator.GetBytes(32);

            byte[] aad = Encoding.UTF8.GetBytes(
    JsonSerializer.Serialize(new
    {
        v = 1,
        user = username,
        key = helloKeyName,
        type = "HELLO",
        device = Environment.MachineName
    }));

            byte[] helloEncrypted =
                WindowsHelloManager.Encrypt(helloKey, helloSecret, aad);

            byte[] helloSalt = RandomNumberGenerator.GetBytes(128);

            byte[] helloKEK =
                Hkdf.HkdfExpand(
                    helloSecret,
                    helloSalt,
                    "HELLO-KEK"u8,
                    32);

            CryptographicOperations.ZeroMemory(helloSecret);

            // =========================================================
            // 5. BUILD COMBINED 3-FACTOR KEK (MUST MATCH LOGIN)
            // =========================================================
            byte[] combinedInput = new byte[96];

            Buffer.BlockCopy(passwordKEK, 0, combinedInput, 0, 32);
            Buffer.BlockCopy(tpmKEK, 0, combinedInput, 32, 32);
            Buffer.BlockCopy(helloKEK, 0, combinedInput, 64, 32);

            byte[] combinedKdfSalt = RandomNumberGenerator.GetBytes(128);

            byte[] combinedKEK =
                Hkdf.HkdfExpand(
                    combinedInput,
                    combinedKdfSalt,
                    "MULTI-FACTOR-KEK"u8,
                    32);

            CryptographicOperations.ZeroMemory(passwordKEK);
            CryptographicOperations.ZeroMemory(tpmKEK);
            CryptographicOperations.ZeroMemory(helloKEK);
            CryptographicOperations.ZeroMemory(combinedInput);

            // =========================================================
            // 6. ENCRYPT JSON FILE
            // =========================================================

            byte[] hmacKey =
                RandomNumberGenerator.GetBytes(64);


            byte[] hmacNonce =
                RandomNumberGenerator.GetBytes(12);

            byte[] hmacCipher =
                new byte[hmacKey.Length];

            byte[] hmacTag =
                new byte[16];


            using (var aes = new AesGcm(combinedKEK, 16))
            {
                aes.Encrypt(
                    hmacNonce,
                    hmacKey,
                    hmacCipher,
                    hmacTag);
            }

            // =========================================================
            // 7. BUILD KEY HIERARCHY (REVERSE OF LOGIN)
            // =========================================================

            byte[] kekL1 = RandomNumberGenerator.GetBytes(32);
            byte[] kekL2 = RandomNumberGenerator.GetBytes(32);

            // unwrap chain (logical structure)
            byte[] wrappedMaster = KeyWrap.AesKeyWrap(kekL2, masterKey);
            byte[] wrappedL2 = KeyWrap.AesKeyWrap(kekL1, kekL2);
            byte[] wrappedL1 = KeyWrap.AesKeyWrap(combinedKEK, kekL1);

            // =========================================================
            // 8. AES-GCM PROTECT KEY BLOB (MATCH LOGIN EXPECTATION)
            // =========================================================

            byte[] gcmSalt = RandomNumberGenerator.GetBytes(128);

            byte[] storageKey =
                Hkdf.HkdfExpand(
                    combinedKEK,
                    gcmSalt,
                    "STORAGE-KEY"u8,
                    32);

            byte[] payload;

            using (var ms = new MemoryStream())
            using (var bw = new BinaryWriter(ms))
            {
                bw.Write(wrappedL1.Length);
                bw.Write(wrappedL1);

                bw.Write(wrappedL2.Length);
                bw.Write(wrappedL2);

                bw.Write(wrappedMaster.Length);
                bw.Write(wrappedMaster);

                payload = ms.ToArray();
            }

            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] ciphertext = new byte[payload.Length];
            byte[] tag = new byte[16];

            using (var aes = new AesGcm(storageKey, 16))
            {
                aes.Encrypt(nonce, payload, ciphertext, tag);
            }

            CryptographicOperations.ZeroMemory(storageKey);
            CryptographicOperations.ZeroMemory(payload);

            // =========================================================
            // 9. CLEANUP TEMPORARY MATERIAL
            // =========================================================
            CryptographicOperations.ZeroMemory(kekL1);
            CryptographicOperations.ZeroMemory(kekL2);
            CryptographicOperations.ZeroMemory(combinedKEK);
            CryptographicOperations.ZeroMemory(masterKey);

            // =========================================================
            // 10. RETURN REGISTRATION RESULT
            // =========================================================

            byte[] sessionSalt =
    RandomNumberGenerator.GetBytes(128);

            byte[] fileRootSalt =
                RandomNumberGenerator.GetBytes(128);

            byte[] memorySalt =
                RandomNumberGenerator.GetBytes(128);

            byte[] ipcSalt =
                RandomNumberGenerator.GetBytes(128);

            return new RegistrationResult
            {
                Blob = new KeyBlob
                {
                    // TPM
                    SealedKekPrivate = sealedBlob.SealedKekPrivate,
                    SealedKekPublic = sealedBlob.SealedKekPublic,
                    Pcrs = sealedBlob.Pcrs,
                    TpmSalt = tpmSalt,

                    // Password
                    PasswordSalt = passwordSalt,
                    PasswordHkdfSalt = passwordHkdfSalt,
                    HkdfSalt = Array.Empty<byte>(),

                    // Hello
                    HelloKeyName = helloKeyName,
                    HelloEncryptedKey = helloEncrypted,
                    HelloSalt = helloSalt,

                    // Protected key
                    EncryptedKeyHierarchy = ciphertext,

                    ChainCipher = Array.Empty<byte>(),
                    ChainNonce = Array.Empty<byte>(),
                    ChainTag = Array.Empty<byte>(),
                    DeviceName = string.Empty,
                    cipherSuite = KeyBlob.CipherSuite.V1,

                    // Combined
                    CombinedKdfSalt = combinedKdfSalt,

                    // GCM container
                    GcmSalt = gcmSalt,
                    GcmNonce = nonce,
                    GcmTag = tag,


                    // Session
                    SessionSalt = sessionSalt,
                    FileRootSalt = fileRootSalt,
                    MemorySalt = memorySalt,
                    IpcSalt = ipcSalt,

                    // Password Derivation Settings
                    ArgonIterations = cryptoConfig.ArgonIterations,
                    ArgonMemory = cryptoConfig.ArgonMemoryKb,
                    ArgonParallelism = cryptoConfig.ArgonParallelism,
                    Kdf = KeyBlob.KdfAlgorithm.Argon2id,

                    // Json
                    HmacKeyCipher = hmacCipher,
                    HmacKeyNonce = hmacNonce,
                    HmacKeyTag = hmacTag
                },
                HmacKey = new HmacKey(hmacKey)
            };
        }
    }
}