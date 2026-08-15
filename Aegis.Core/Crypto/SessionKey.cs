using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto
{
    public sealed class SessionKey : IDisposable
    {
        private byte[] _key;
        private bool _disposed;

        internal SessionKey(byte[] key)
        {
            _key = key;
        }

        public byte[] Export()
        {
            if (_key == null)
                throw new ObjectDisposedException(nameof(SessionKey));

            return _key.ToArray();
        }

        public byte[] DeriveKey(
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> info,
            int length)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(SessionKey));

            return Hkdf.HkdfExpand(
                _key,
                salt,
                info,
                length);
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            CryptographicOperations.ZeroMemory(_key);
            _key = Array.Empty<byte>();
            _disposed = true;
        }
    }
}
