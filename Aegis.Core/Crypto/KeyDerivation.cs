using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Tpm2Lib;

namespace Aegis.Core.Crypto
{
    internal static class KeyDerivation
    {
        private const int RequiredSaltCount = 9;

        public static DerivedKeys DeriveKeys(
            FileKey fileKey,
            byte[][] salts)
        {
            if (fileKey == null)
                throw new ArgumentNullException(nameof(fileKey));

            if (salts == null ||
                salts.Length != RequiredSaltCount)
            {
                throw new ArgumentException(
                    $"Exactly {RequiredSaltCount} salts are required.",
                    nameof(salts));
            }

            byte[] xChaCha = null!;
            byte[] threefish = null!;
            byte[] serpent = null!;
            byte[] aes = null!;
            byte[] shuffle = null!;
            byte[] threefishHmac = null!;
            byte[] serpentHmac = null!;
            byte[] aesHmac = null!;
            byte[] headerHmac = null!;

            try
            {
                // Root encryption material
                var rootEnc =
                    fileKey.EncryptionKey;

                // Root HMAC material
                var rootHmac =
                    fileKey.HmacKey;

                xChaCha = Hkdf.HkdfExpand(
                    rootEnc,
                    salts[0],
                    "XChaCha20-Poly1305"u8,
                    32);

                threefish = Hkdf.HkdfExpand(
                    rootEnc,
                    salts[1],
                    "Threefish-1024"u8,
                    128);

                serpent = Hkdf.HkdfExpand(
                    rootEnc,
                    salts[2],
                    "Serpent-256-Key"u8,
                    32);

                aes = Hkdf.HkdfExpand(
                    rootEnc,
                    salts[3],
                    "AES-256"u8,
                    32);

                shuffle = Hkdf.HkdfExpand(
                    rootEnc,
                    salts[4],
                    "Shuffle-Layer"u8,
                    128);

                threefishHmac = Hkdf.HkdfExpand(
                    rootHmac,
                    salts[5],
                    "Threefish-1024-HMAC"u8,
                    64);

                serpentHmac = Hkdf.HkdfExpand(
                    rootHmac,
                    salts[6],
                    "Serpent-256-HMAC"u8,
                    64);

                aesHmac = Hkdf.HkdfExpand(
                    rootHmac,
                    salts[7],
                    "AES-256-HMAC"u8,
                    64);

                headerHmac = Hkdf.HkdfExpand(
                    rootHmac,
                    salts[8],
                    "FILE-HEADER-HMAC"u8,
                    64);

                return new DerivedKeys(
                    xChaCha,
                    threefish,
                    serpent,
                    aes,
                    shuffle,
                    threefishHmac,
                    serpentHmac,
                    aesHmac,
                    headerHmac,
                    salts);
            }

            catch
            {
                CryptographicOperations.ZeroMemory(xChaCha);
                CryptographicOperations.ZeroMemory(threefish);
                CryptographicOperations.ZeroMemory(serpent);
                CryptographicOperations.ZeroMemory(aes);
                CryptographicOperations.ZeroMemory(shuffle);
                CryptographicOperations.ZeroMemory(threefishHmac);
                CryptographicOperations.ZeroMemory(serpentHmac);
                CryptographicOperations.ZeroMemory(aesHmac);
                CryptographicOperations.ZeroMemory(headerHmac);

                throw;
            }
        }
    }
}
