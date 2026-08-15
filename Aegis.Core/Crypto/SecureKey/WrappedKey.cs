using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto.SecureKey
{
    internal sealed class WrappedKey : IDisposable
    {
        private byte[]? _wrapped;

        private bool _disposed;


        private WrappedKey(
            byte[] wrapped)
        {
            _wrapped = wrapped;
        }


        internal static WrappedKey Wrap(
            ReadOnlySpan<byte> kek,
            ReadOnlySpan<byte> plaintext)
        {
            if (kek.Length != 32)
                throw new ArgumentException(
                    "KEK must be 32 bytes.",
                    nameof(kek));

            if (plaintext.Length == 0)
                throw new ArgumentException(
                    "Key cannot be empty.",
                    nameof(plaintext));

            byte[] wrapped =
                KeyWrap.AesKeyWrap(
                    kek.ToArray(),
                    plaintext.ToArray());

            return new WrappedKey(
                wrapped);
        }


        internal byte[] Export()
        {
            if (_disposed)
                throw new ObjectDisposedException(
                    nameof(WrappedKey));

            return _wrapped!.ToArray();
        }


        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            if (_wrapped != null)
            {
                CryptographicOperations.ZeroMemory(
                    _wrapped);

                _wrapped = null;
            }

            GC.SuppressFinalize(this);
        }
    }
}
