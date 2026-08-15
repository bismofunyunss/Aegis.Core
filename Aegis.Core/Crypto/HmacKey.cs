using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto
{
    public sealed class HmacKey : IDisposable
    {
        private byte[]? _key;

        internal HmacKey(byte[] key)
        {
            _key = key ??
                   throw new ArgumentNullException(nameof(key));
        }

        public Span<byte> Key =>
            _key ?? throw new ObjectDisposedException(nameof(HmacKey));

        public byte[] ComputeHash(byte[] data)
        {
            if (_key == null)
                throw new ObjectDisposedException(nameof(HmacKey));

            using var hmac =
                new HMACSHA3_512(_key);

            return hmac.ComputeHash(data);
        }


        public bool Verify(
            byte[] data,
            byte[] expected)
        {
            byte[] actual = ComputeHash(data);

            try
            {
                return CryptographicOperations.FixedTimeEquals(
                    actual,
                    expected);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actual);
            }
        }


        public void Dispose()
        {
            if (_key == null)
                return;

            CryptographicOperations.ZeroMemory(_key);

            _key = null;

            GC.SuppressFinalize(this);
        }


        ~HmacKey()
        {
            Dispose();
        }
    }
}
