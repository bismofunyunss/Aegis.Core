using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto.SecureKey
{
    internal sealed class TpmProtectedKek : IDisposable
    {
        private byte[]? _wrappedKek;
        private bool _disposed;

        internal TpmProtectedKek(
            byte[] wrappedKek)
        {
            ArgumentNullException.ThrowIfNull(wrappedKek);

            if (wrappedKek.Length == 0)
            {
                throw new ArgumentException(
                    "Wrapped KEK cannot be empty.",
                    nameof(wrappedKek));
            }

            _wrappedKek =
                wrappedKek.ToArray();
        }

        internal byte[] Export()
        {
            ObjectDisposedException.ThrowIf(
                _disposed,
                this);

            return _wrappedKek!.ToArray();
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            if (_wrappedKek != null)
            {
                CryptographicOperations.ZeroMemory(
                    _wrappedKek);

                _wrappedKek = null;
            }

            GC.SuppressFinalize(this);
        }
    }
}
