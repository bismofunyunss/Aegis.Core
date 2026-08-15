using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto
{
    internal static class WindowsHelloManager
    {
        public static CngKey GetOrCreateHelloKey(string keyName)
        {
            if (CngKey.Exists(keyName, CngProvider.MicrosoftPlatformCryptoProvider))
                return CngKey.Open(keyName, CngProvider.MicrosoftPlatformCryptoProvider);

            var creationParams = new CngKeyCreationParameters
            {
                Provider = CngProvider.MicrosoftPlatformCryptoProvider, // TPM-backed if available
                KeyUsage = CngKeyUsages.Decryption,
                ExportPolicy = CngExportPolicies.None,
                UIPolicy = new CngUIPolicy(
                    CngUIProtectionLevels.ProtectKey, // PIN/biometric
                    friendlyName: "Aegis Hello Key",
                    description: "Authorize access to master key",
                    useContext: null,
                    creationTitle: "Confirm your identity")
            };

            return CngKey.Create(CngAlgorithm.Rsa, keyName, creationParams);
        }

        public static byte[] Encrypt(CngKey key, byte[] plaintext, byte[] aad)
        {
            if (aad == null || aad.Length == 0)
                throw new ArgumentException("AAD required");

            byte[] domain = "AEGIS-HELLO-V1"u8.ToArray();
            byte[] fullAad = Helpers.CombineArrays.Combine(domain, aad);

            byte[] aesKey = RandomNumberGenerator.GetBytes(32);

            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            using (var aes = new AesGcm(aesKey, 16))
                aes.Encrypt(nonce, plaintext, ciphertext, tag, fullAad);

            byte[] wrappedKey;
            using (var rsa = new RSACng(key))
                wrappedKey = rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);

            CryptographicOperations.ZeroMemory(aesKey);

            using var ms = new MemoryStream();
            using var bw = new BinaryWriter(ms);

            bw.Write((byte)1);
            bw.Write(wrappedKey.Length);
            bw.Write(wrappedKey);
            bw.Write(nonce);
            bw.Write(tag);
            bw.Write(ciphertext);

            return ms.ToArray();
        }

        public static byte[] Decrypt(CngKey key, byte[] blob, byte[] aad)
        {
            if (aad == null || aad.Length == 0)
                throw new ArgumentException("AAD required");

            byte[] domain = "AEGIS-HELLO-V1"u8.ToArray();
            byte[] fullAad = Helpers.CombineArrays.Combine(domain, aad);

            using var ms = new MemoryStream(blob);
            using var br = new BinaryReader(ms);

            byte version = br.ReadByte();
            if (version != 1)
                throw new CryptographicException("Invalid version");

            int wrappedLen = br.ReadInt32();
            if (wrappedLen <= 0 || wrappedLen > 8192)
                throw new CryptographicException("Invalid wrapped key length");

            byte[] wrappedKey = br.ReadBytes(wrappedLen);

            byte[] nonce = br.ReadBytes(12);
            byte[] tag = br.ReadBytes(16);
            byte[] ciphertext = br.ReadBytes((int)(ms.Length - ms.Position));

            byte[] aesKey;
            using (var rsa = new RSACng(key))
                aesKey = rsa.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA256);

            byte[] plaintext = new byte[ciphertext.Length];

            using (var aes = new AesGcm(aesKey, 16))
                aes.Decrypt(nonce, ciphertext, tag, plaintext, fullAad);

            CryptographicOperations.ZeroMemory(aesKey);

            return plaintext;
        }
    }
}
