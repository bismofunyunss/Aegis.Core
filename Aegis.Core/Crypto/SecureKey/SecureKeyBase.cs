using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.Crypto.SecureKey
{
    public abstract class SecureKeyBase : IDisposable
    {
        private bool _disposed;

        internal SecureBuffer Buffer { get; }

        protected SecureKeyBase(
            ReadOnlySpan<byte> key)
        {
            if (key.Length == 0)
            {
                throw new ArgumentException(
                    "Key cannot be empty.",
                    nameof(key));
            }

            Buffer =
                new SecureBuffer(key);
        }

        public int Length
        {
            get
            {
                ThrowIfDisposed();

                return Buffer.Length;
            }
        }

        public Span<byte> Key
        {
            get
            {
                ThrowIfDisposed();

                return Buffer.AsSpan();
            }
        }

        protected ReadOnlySpan<byte> KeyReadOnly
        {
            get
            {
                ThrowIfDisposed();

                return Buffer.AsReadOnlySpan();
            }
        }

        protected void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(
                _disposed,
                this);
        }

        protected virtual void Dispose(
            bool disposing)
        {
            if (_disposed)
                return;

            _disposed = true;

            if (disposing)
            {
                Buffer.Dispose();
            }
        }

        public void Dispose()
        {
            Dispose(true);

            GC.SuppressFinalize(this);
        }
    }
}
