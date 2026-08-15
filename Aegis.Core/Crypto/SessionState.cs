using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.Crypto
{
    internal sealed class SessionState
    {
        public required string SessionId { get; init; }

        public required string Username { get; init; }

        public required ServerCryptoSession Session { get; init; }

        public required DateTime CreatedUtc { get; init; }

        public required DateTime ExpiresUtc { get; set; }

        public ulong LastCounter { get; set; }
        public object SyncRoot { get; } = new();

    }
}
