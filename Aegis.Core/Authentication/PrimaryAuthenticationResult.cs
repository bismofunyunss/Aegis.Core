using Aegis.Core.Crypto;
using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.Authentication
{
    internal sealed class PrimaryAuthenticationResult : IDisposable
    {
        public required AccountRootKey AccountRootKey { get; init; }

        public required FileRootKey FileRootKey { get; init; }

        public required MemoryProtectionKey MemoryProtectionKey { get; init; }

        public required IpcWrappingKey IpcWrappingKey { get; init; }

        public required HmacKey HmacKey { get; init; }

        private bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            HmacKey.Dispose();
            IpcWrappingKey.Dispose();
            MemoryProtectionKey.Dispose();
            FileRootKey.Dispose();
            AccountRootKey.Dispose();

            GC.SuppressFinalize(this);
        }
    }
}
