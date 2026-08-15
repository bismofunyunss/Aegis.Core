using Aegis.Core.Crypto;
using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.Authentication
{
    internal sealed class PendingLoginAuthentication : IDisposable
    {
        private bool _disposed;

        public PendingLoginAuthentication(
            string username,
            AccountRootKey accountRootKey,
            FileRootKey fileRootKey,
            MemoryProtectionKey memoryKey,
            IpcWrappingKey ipcWrappingKey,
            HmacKey hmacKey,
            TimeSpan lifetime)
        {
            Username = username;

            AccountRootKey = accountRootKey;
            FileRootKey = fileRootKey;
            MemoryProtectionKey = memoryKey;
            IpcWrappingKey = ipcWrappingKey;
            HmacKey = hmacKey;

            ExpiresAtUtc =
                DateTimeOffset.UtcNow.Add(lifetime);
        }

        public string Username { get; }

        public AccountRootKey AccountRootKey { get; private set; }

        public FileRootKey FileRootKey { get; private set; }

        public MemoryProtectionKey MemoryProtectionKey { get; private set; }

        public IpcWrappingKey IpcWrappingKey { get; private set; }

        public HmacKey HmacKey { get; private set; }

        public DateTimeOffset ExpiresAtUtc { get; }

        public bool IsExpired =>
            DateTimeOffset.UtcNow >= ExpiresAtUtc;

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
