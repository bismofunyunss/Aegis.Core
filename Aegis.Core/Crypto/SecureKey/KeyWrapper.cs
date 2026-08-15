using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto.SecureKey
{
    internal static class KeyWrapper
    {
        // ============================================================
        // WRAP SECURE KEY
        //
        // SecureBuffer
        //      ↓
        // AES-KW / RFC 5649
        //      ↓
        // wrapped byte[]
        // ============================================================

        internal static byte[] Wrap(
            AesKek kek,
            SecureBuffer key)
        {
            ArgumentNullException.ThrowIfNull(kek);
            ArgumentNullException.ThrowIfNull(key);

            return KeyWrap.AesKeyWrap(
                kek.Export(),
                key.ToArrayCopy());
        }


        // ============================================================
        // WRAP BYTE ARRAY
        //
        // Useful when the source key is temporarily represented as
        // a byte[].
        // ============================================================

        internal static byte[] Wrap(
            AesKek kek,
            ReadOnlySpan<byte> key)
        {
            ArgumentNullException.ThrowIfNull(kek);

            if (key.IsEmpty)
            {
                throw new ArgumentException(
                    "Key cannot be empty.",
                    nameof(key));
            }

            return KeyWrap.AesKeyWrap(
                kek.Key.ToArray(),
                key.ToArray());
        }


        // ============================================================
        // UNWRAP TO SECURE BUFFER
        //
        // wrapped byte[]
        //      ↓
        // AES-KW / RFC 5649
        //      ↓
        // temporary plaintext byte[]
        //      ↓
        // SecureBuffer
        //
        // The temporary plaintext array is zeroed immediately after
        // being copied into SecureBuffer.
        // ============================================================

        internal static SecureBuffer Unwrap(
            AesKek kek,
            ReadOnlySpan<byte> wrappedKey)
        {
            ArgumentNullException.ThrowIfNull(kek);

            if (wrappedKey.IsEmpty)
            {
                throw new ArgumentException(
                    "Wrapped key cannot be empty.",
                    nameof(wrappedKey));
            }

            byte[]? plaintext = null;

            try
            {
                plaintext =
                    KeyWrap.AesKeyUnwrap(
                        kek.Key.ToArray(),
                        wrappedKey.ToArray());

                if (plaintext.Length == 0)
                {
                    throw new CryptographicException(
                        "Unwrapped key is empty.");
                }

                return new SecureBuffer(
                    plaintext);
            }
            finally
            {
                if (plaintext != null)
                {
                    CryptographicOperations.ZeroMemory(
                        plaintext);
                }
            }
        }
    }
}
