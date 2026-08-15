using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Aegis.Core.Crypto.SecureKey;

namespace Aegis.Core.Crypto
{
    internal sealed class HmacSha3Stream : IDisposable
    {
        private readonly HMACSHA3_512 _hmac;

        private readonly object _sync = new();

        private bool _disposed;
        private bool _finalized;


        // ============================================================
        // CONSTRUCTOR
        // ============================================================

        public HmacSha3Stream(
            byte[] key)
        {
            ArgumentNullException.ThrowIfNull(
                key);

            _hmac =
                new HMACSHA3_512(
                    key);
        }

        internal static byte[] ComputeSha3_512(
            SecureBuffer key,
            ReadOnlySpan<byte> data)
        {
            ArgumentNullException.ThrowIfNull(
                key);

            using HmacSha3Stream hmac =
                new HmacSha3Stream(
                    key.ToArrayCopy());

            hmac.Update(
                data);

            return hmac.Final();
        }

        // ============================================================
        // DISPOSE
        // ============================================================

        public void Dispose()
        {
            lock (_sync)
            {
                if (_disposed) return;

                _hmac.Dispose();

                _disposed = true;
            }

            GC.SuppressFinalize(this);
        }


        // ============================================================
        // UPDATE - BYTE ARRAY
        // ============================================================

        public void Update(
            byte[] data,
            int offset,
            int len)
        {
            ArgumentNullException.ThrowIfNull(
                data);

            if (offset < 0 ||
                len < 0 ||
                offset > data.Length - len)
                throw new ArgumentOutOfRangeException();

            lock (_sync)
            {
                ThrowIfInvalid();

                _hmac.TransformBlock(
                    data,
                    offset,
                    len,
                    null,
                    0);
            }
        }


        // ============================================================
        // UPDATE - SPAN
        // ============================================================

        public void Update(
            ReadOnlySpan<byte> data)
        {
            lock (_sync)
            {
                ThrowIfInvalid();

                if (data.IsEmpty) return;

                var temporary =
                    data.ToArray();

                try
                {
                    _hmac.TransformBlock(
                        temporary,
                        0,
                        temporary.Length,
                        null,
                        0);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        temporary);
                }
            }
        }


        // ============================================================
        // FINAL
        // ============================================================

        public byte[] Final()
        {
            lock (_sync)
            {
                ThrowIfInvalid();

                _finalized = true;

                _hmac.TransformFinalBlock(
                    Array.Empty<byte>(),
                    0,
                    0);

                var result =
                    _hmac.Hash?.ToArray()
                    ?? throw new CryptographicException(
                        "HMAC finalization failed.");

                return result;
            }
        }


        // ============================================================
        // STATE VALIDATION
        // ============================================================

        private void ThrowIfInvalid()
        {
            if (_disposed)
                throw new ObjectDisposedException(
                    nameof(HmacSha3Stream));

            if (_finalized)
                throw new InvalidOperationException(
                    "HMAC already finalized.");
        }
    }
}
