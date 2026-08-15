using Aegis.Contracts;
using Aegis.Core.Crypto;
using Aegis.Core.Storage;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Authentication
{
    internal sealed class PendingAuthentication : IDisposable
    {
        public PendingAuthentication(
            string username,
            KeyBlob blob,
            byte[] combinedKek,
            HmacKey hmacKey,
            TimeSpan lifetime)
        {
            Username = username;
            Blob = blob;
            CombinedKek = combinedKek;
            HmacKey = hmacKey;
            ExpiresAt = DateTimeOffset.UtcNow.Add(lifetime);
        }

        public string Username { get; }

        public KeyBlob Blob { get; }

        public byte[] CombinedKek { get; }

        public HmacKey HmacKey { get; }

        public DateTimeOffset ExpiresAt { get; }

        public bool IsExpired =>
            DateTimeOffset.UtcNow >= ExpiresAt;

        public void Dispose()
        {
            HmacKey.Dispose();
        }
    }
}
