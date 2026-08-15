using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.IPC
{
    public sealed class VaultSession
    {
        public string SessionId { get; set; } = "";

        // replay protection
        public ulong LastCounter { get; set; }

        // expiration
        public DateTime ExpiresUtc { get; set; }

        // optional username tracking
        public string Username { get; set; } = "";
    }
}
