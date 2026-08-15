using System;
using System.Collections.Generic;
using System.Text;
using Aegis.Core.Crypto.SecureKey;

namespace Aegis.Core.Crypto
{
    internal sealed class KeyEncryptionKey : SecureKeyBase
    {
        internal KeyEncryptionKey(
            ReadOnlySpan<byte> key)
            : base(key)
        {
            if (key.Length != 32)
            {
                throw new ArgumentException(
                    "A key-encryption key must be exactly 32 bytes.",
                    nameof(key));
            }
        }
    }
}
