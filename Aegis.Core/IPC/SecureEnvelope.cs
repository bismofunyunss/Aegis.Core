using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.IPC
{
    public sealed class SecureEnvelope
    {
        public string SessionId { get; set; } = string.Empty;

        public ulong Counter { get; set; }

        public string Command { get; set; } = string.Empty;

        public byte[] Nonce { get; set; } = [];

        public byte[] Ciphertext { get; set; } = [];

        public byte[] Tag { get; set; } = [];
    }
}
