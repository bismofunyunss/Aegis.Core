using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto
{
internal static class GcmUtil
    {
        private const int NonceSize = 12;
        private const int TagSize = 16;

        public static byte[] Encrypt(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> key)
        {
            byte[] nonce =
                RandomNumberGenerator.GetBytes(
                    NonceSize);

            byte[] ciphertext =
                new byte[plaintext.Length];

            byte[] tag =
                new byte[TagSize];

            try
            {
                using var aes =
                    new AesGcm(
                        key,
                        tagSizeInBytes: TagSize);

                aes.Encrypt(
                    nonce,
                    plaintext,
                    ciphertext,
                    tag);

                byte[] result =
                    new byte[
                        NonceSize +
                        TagSize +
                        ciphertext.Length];

                nonce.CopyTo(
                    result.AsSpan(
                        0,
                        NonceSize));

                tag.CopyTo(
                    result.AsSpan(
                        NonceSize,
                        TagSize));

                ciphertext.CopyTo(
                    result.AsSpan(
                        NonceSize +
                        TagSize));

                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    nonce);

                CryptographicOperations.ZeroMemory(
                    tag);

                CryptographicOperations.ZeroMemory(
                    ciphertext);
            }
        }

        public static byte[] Decrypt(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> key)
        {
            if (data.Length < NonceSize + TagSize)
            {
                throw new ArgumentException(
                    "Encrypted data is too short.",
                    nameof(data));
            }

            ReadOnlySpan<byte> nonce =
                data.Slice(
                    0,
                    NonceSize);

            ReadOnlySpan<byte> tag =
                data.Slice(
                    NonceSize,
                    TagSize);

            ReadOnlySpan<byte> ciphertext =
                data.Slice(
                    NonceSize + TagSize);

            byte[] plaintext =
                new byte[ciphertext.Length];

            try
            {
                using var aes =
                    new AesGcm(
                        key,
                        tagSizeInBytes: TagSize);

                aes.Decrypt(
                    nonce,
                    ciphertext,
                    tag,
                    plaintext);

                return plaintext;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(
                    plaintext);

                throw;
            }
        }
    }
}
