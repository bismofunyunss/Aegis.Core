using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto
{
    internal static class KeyProtector
    {
        private const int KeySize = 32;
        private const int NonceSize = 12;
        private const int TagSize = 16;

        public static byte[] Encrypt(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> associatedData = default)
        {
            if (key.Length != KeySize)
            {
                throw new ArgumentException(
                    "Key must be exactly 32 bytes.",
                    nameof(key));
            }

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
                        TagSize);

                aes.Encrypt(
                    nonce,
                    plaintext,
                    ciphertext,
                    tag,
                    associatedData);

                byte[] result =
                    new byte[
                        NonceSize +
                        TagSize +
                        ciphertext.Length];

                nonce.CopyTo(
                    result,
                    0);

                tag.CopyTo(
                    result,
                    NonceSize);

                ciphertext.CopyTo(
                    result,
                    NonceSize + TagSize);

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
            ReadOnlySpan<byte> encrypted,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> associatedData = default)
        {
            if (key.Length != KeySize)
            {
                throw new ArgumentException(
                    "Key must be exactly 32 bytes.",
                    nameof(key));
            }

            if (encrypted.Length <
                NonceSize + TagSize)
            {
                throw new CryptographicException(
                    "Encrypted key blob is too short.");
            }

            ReadOnlySpan<byte> nonce =
                encrypted[..NonceSize];

            ReadOnlySpan<byte> tag =
                encrypted.Slice(
                    NonceSize,
                    TagSize);

            ReadOnlySpan<byte> ciphertext =
                encrypted[
                    (NonceSize + TagSize)..];

            byte[] plaintext =
                new byte[ciphertext.Length];

            try
            {
                using var aes =
                    new AesGcm(
                        key,
                        TagSize);

                aes.Decrypt(
                    nonce,
                    ciphertext,
                    tag,
                    plaintext,
                    associatedData);

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
