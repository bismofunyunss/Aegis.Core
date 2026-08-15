using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto
{
    internal static class Hkdf
    {
        // ============================================================
        // HMAC-SHA3-512
        // ============================================================

        private const int HashSize = 64;

        /*
         * RFC 5869:
         *
         *   L <= 255 * HashLen
         *
         * For SHA3-512:
         *
         *   255 * 64 = 16,320 bytes
         */
        private const int MaxOutputLength =
            255 * HashSize;


        // ============================================================
        // HKDF-EXTRACT + HKDF-EXPAND
        //
        //
        // Hkdf.HKDFExpand(
        //     ikm,
        //     salt,
        //     info,
        //     length);
        //
        // ============================================================

        public static byte[] HkdfExpand(
            ReadOnlySpan<byte> ikm,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            int length)
        {
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(length));
            }

            if (length > MaxOutputLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(length),
                    length,
                    $"HKDF output cannot exceed {MaxOutputLength} bytes.");
            }

            if (length == 0)
            {
                return Array.Empty<byte>();
            }


            // ========================================================
            // HKDF-EXTRACT
            //
            // PRK = HMAC-SHA3-512(
            //     salt,
            //     IKM
            // )
            //
            // RFC 5869 says an omitted/empty salt is HashLen
            // zero bytes.
            // ========================================================

            Span<byte> prk =
                stackalloc byte[HashSize];

            try
            {
                Span<byte> zeroSalt =
                    stackalloc byte[HashSize];

                zeroSalt.Clear();

                ReadOnlySpan<byte> extractSalt =
                    salt.Length == 0
                        ? zeroSalt
                        : salt;

                /*
                 * SHA3-512 HMAC produces exactly 64 bytes.
                 */
                if (!HMACSHA3_512.TryHashData(
                        extractSalt,
                        ikm,
                        prk,
                        out int prkWritten) ||
                    prkWritten != HashSize)
                {
                    throw new CryptographicException(
                        "HMAC-SHA3-512 failed during HKDF-Extract.");
                }


                // ====================================================
                // HKDF-EXPAND
                // ====================================================

                byte[] okm =
                    new byte[length];

                Span<byte> previous =
                    stackalloc byte[HashSize];

                previous.Clear();

                bool previousInitialized =
                    false;

                try
                {
                    int offset = 0;

                    byte counter = 1;

                    while (offset < length)
                    {
                        /*
                         * We need:
                         *
                         * T(previous)
                         * ||
                         * info
                         * ||
                         * counter
                         *
                         * The maximum size here is:
                         *
                         * 64 + info.Length + 1
                         *
                         * Your domain strings are tiny, so stackalloc
                         * is appropriate.
                         */
                        int inputLength =
                            checked(
                                (previousInitialized
                                    ? HashSize
                                    : 0)
                                +
                                info.Length
                                +
                                1);

                        Span<byte> input =
                            stackalloc byte[inputLength];

                        input.Clear();

                        int position = 0;

                        if (previousInitialized)
                        {
                            previous.CopyTo(
                                input);

                            position +=
                                HashSize;
                        }

                        info.CopyTo(
                            input[position..]);

                        position +=
                            info.Length;

                        input[position] =
                            counter;


                        Span<byte> current =
                            stackalloc byte[HashSize];

                        current.Clear();

                        try
                        {
                            if (!HMACSHA3_512.TryHashData(
                                    prk,
                                    input,
                                    current,
                                    out int written) ||
                                written != HashSize)
                            {
                                throw new CryptographicException(
                                    "HMAC-SHA3-512 failed during HKDF-Expand.");
                            }

                            int remaining =
                                length - offset;

                            int copyLength =
                                Math.Min(
                                    HashSize,
                                    remaining);

                            current[..copyLength]
                                .CopyTo(
                                    okm.AsSpan(
                                        offset,
                                        copyLength));

                            offset +=
                                copyLength;


                            // ========================================
                            // T(i) becomes T(i-1) for next iteration.
                            // ========================================

                            current.CopyTo(
                                previous);

                            previousInitialized =
                                true;

                            if (counter == 255 &&
                                offset < length)
                            {
                                throw new CryptographicException(
                                    "HKDF output length exceeded.");
                            }

                            counter++;
                        }
                        finally
                        {
                            /*
                             * Explicitly erase T(i).
                             */
                            CryptographicOperations
                                .ZeroMemory(
                                    current);

                            /*
                             * Explicitly erase the constructed
                             * HMAC input.
                             */
                            CryptographicOperations
                                .ZeroMemory(
                                    input);
                        }
                    }

                    return okm;
                }
                catch
                {
                    /*
                     * Never leave partially generated key material
                     * alive if HKDF fails.
                     */
                    CryptographicOperations
                        .ZeroMemory(
                            okm);

                    throw;
                }
                finally
                {
                    CryptographicOperations
                        .ZeroMemory(
                            previous);
                }
            }
            finally
            {
                /*
                 * PRK is sensitive intermediate key material.
                 */
                CryptographicOperations
                    .ZeroMemory(
                        prk);
            }
        }

        public static void HKDFExpandFast(
    ReadOnlySpan<byte> ikm,
    ReadOnlySpan<byte> salt,
    ReadOnlySpan<byte> info,
    Span<byte> output)
        {
            const int HashSize = 64;
            const int MaxOutputLength = 255 * HashSize;

            if (output.Length > MaxOutputLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(output),
                    output.Length,
                    $"HKDF output cannot exceed {MaxOutputLength} bytes.");
            }

            if (output.Length == 0)
            {
                return;
            }

            // ============================================================
            // HKDF-EXTRACT
            //
            // PRK = HMAC-SHA3-512(salt, IKM)
            //
            // RFC 5869:
            // Empty salt is HashLen zero bytes.
            // ============================================================

            Span<byte> prk =
                stackalloc byte[HashSize];

            try
            {
                Span<byte> zeroSalt =
                    stackalloc byte[HashSize];

                zeroSalt.Clear();

                ReadOnlySpan<byte> extractSalt =
                    salt.IsEmpty
                        ? zeroSalt
                        : salt;

                if (!HMACSHA3_512.TryHashData(
                        extractSalt,
                        ikm,
                        prk,
                        out int prkWritten) ||
                    prkWritten != HashSize)
                {
                    throw new CryptographicException(
                        "HMAC-SHA3-512 failed during HKDF-Extract.");
                }


                // ========================================================
                // HKDF-EXPAND
                //
                // T(0) = empty
                //
                // T(i) =
                //     HMAC(
                //         PRK,
                //         T(i-1) || info || counter
                //     )
                // ========================================================

                Span<byte> previous =
                    stackalloc byte[HashSize];

                previous.Clear();

                bool previousInitialized = false;

                int offset = 0;

                byte counter = 1;

                try
                {
                    while (offset < output.Length)
                    {
                        // ------------------------------------------------
                        // Construct:
                        //
                        // T(previous) || info || counter
                        // ------------------------------------------------

                        int inputLength =
                            checked(
                                (previousInitialized
                                    ? HashSize
                                    : 0)
                                +
                                info.Length
                                +
                                1);

                        Span<byte> input =
                            inputLength <= 4096
                                ? stackalloc byte[inputLength]
                                : throw new ArgumentException(
                                    "HKDF info is too large.",
                                    nameof(info));

                        input.Clear();

                        int position = 0;

                        if (previousInitialized)
                        {
                            previous.CopyTo(
                                input);

                            position +=
                                HashSize;
                        }

                        info.CopyTo(
                            input[position..]);

                        position +=
                            info.Length;

                        input[position] =
                            counter;


                        // ------------------------------------------------
                        // Calculate T(i)
                        // ------------------------------------------------

                        Span<byte> current =
                            stackalloc byte[HashSize];

                        current.Clear();

                        try
                        {
                            if (!HMACSHA3_512.TryHashData(
                                    prk,
                                    input,
                                    current,
                                    out int written) ||
                                written != HashSize)
                            {
                                throw new CryptographicException(
                                    "HMAC-SHA3-512 failed during HKDF-Expand.");
                            }


                            // ------------------------------------------------
                            // Copy requested output.
                            // ------------------------------------------------

                            int remaining =
                                output.Length - offset;

                            int copyLength =
                                Math.Min(
                                    HashSize,
                                    remaining);

                            current[..copyLength]
                                .CopyTo(
                                    output.Slice(
                                        offset,
                                        copyLength));

                            offset +=
                                copyLength;


                            // ------------------------------------------------
                            // T(i) becomes T(i-1)
                            // ------------------------------------------------

                            current.CopyTo(
                                previous);

                            previousInitialized =
                                true;


                            // ------------------------------------------------
                            // RFC 5869 permits counters 1..255 only.
                            // ------------------------------------------------

                            if (offset < output.Length)
                            {
                                if (counter == 255)
                                {
                                    throw new CryptographicException(
                                        "HKDF output length exceeded.");
                                }

                                counter++;
                            }
                        }
                        finally
                        {
                            // Erase T(i).
                            CryptographicOperations.ZeroMemory(
                                current);

                            // Erase constructed HMAC input.
                            CryptographicOperations.ZeroMemory(
                                input);
                        }
                    }
                }
                catch
                {
                    // Never leave partially generated key material
                    // in the caller's output buffer.
                    CryptographicOperations.ZeroMemory(
                        output);

                    throw;
                }
                finally
                {
                    // Erase T(i-1).
                    CryptographicOperations.ZeroMemory(
                        previous);
                }
            }
            finally
            {
                // Erase PRK.
                CryptographicOperations.ZeroMemory(
                    prk);
            }
        }
    }
}
