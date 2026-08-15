using Aegis.Core.Crypto;
using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.Authentication
{
    internal sealed class PendingTotpEnrollment : IDisposable
    {
        public required string Id { get; init; }

        public required string Username { get; init; }

        public required HmacKey HmacKey { get; init; }

        public required DateTimeOffset ExpiresAt { get; init; }

        public bool IsExpired =>
            DateTimeOffset.UtcNow >= ExpiresAt;

        public void Dispose()
        {
            HmacKey.Dispose();
        }
    }
}
