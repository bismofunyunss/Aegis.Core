using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.FileEncryption
{
    internal sealed class CryptoChunk
    {
        public long Index;

        public long ByteOffset;

        public byte[]? Buffer;

        public int Length;

        public bool BufferPooled;

        public byte[]? AeadTag;

        public byte[]? CiphertextForHmac;

        public int CiphertextLength;

        public bool CiphertextForHmacPooled;

        public ulong AeadCounter;

        public byte[]? HmacBuffer;

        public int HmacLength;

        public bool HmacBufferPooled;
    }
}
