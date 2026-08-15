using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto.SecureKey
{
    internal sealed class AesKek : IDisposable
    {
        private SecureBuffer? _buffer;

        private bool _disposed;


        // ============================================================
        // GENERATE
        // ============================================================

        public static AesKek Generate()
        {
            byte[] key =
                RandomNumberGenerator.GetBytes(32);

            try
            {
                return new AesKek(
                    key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    key);
            }
        }


        // ============================================================
        // CONSTRUCTOR
        // ============================================================

        internal AesKek(
            ReadOnlySpan<byte> key)
        {
            if (key.Length != 32)
            {
                throw new ArgumentException(
                    "AES KEK must be exactly 32 bytes.",
                    nameof(key));
            }

            _buffer =
                new SecureBuffer(
                    key);
        }


        // ============================================================
        // KEY ACCESS
        // ============================================================

        internal ReadOnlySpan<byte> Key
        {
            get
            {
                ThrowIfDisposed();

                return _buffer!
                    .AsReadOnlySpan();
            }
        }


        // ============================================================
        // EXPORT
        //
        // Only use when absolutely necessary.
        // ============================================================

        internal byte[] Export()
        {
            ThrowIfDisposed();

            return _buffer!
                .ToArrayCopy();
        }


        // ============================================================
        // DISPOSE
        // ============================================================

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            _buffer?.Dispose();

            _buffer = null;

            GC.SuppressFinalize(
                this);
        }


        // ============================================================
        // DISPOSE CHECK
        // ============================================================

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(
                _disposed,
                this);
        }
    }
}
