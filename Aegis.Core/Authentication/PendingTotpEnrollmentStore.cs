using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Aegis.Core.Crypto;

namespace Aegis.Core.Authentication
{
    internal sealed class PendingTotpEnrollmentStore
    {
        private readonly object _sync = new();

        private readonly Dictionary<
            string,
            PendingTotpEnrollment> _pending =
            new();

        public string Add(
            string username,
            HmacKey hmacKey,
            TimeSpan lifetime)
        {
            if (string.IsNullOrWhiteSpace(username))
                throw new ArgumentException(
                    "Username is required.",
                    nameof(username));

            if (hmacKey == null)
                throw new ArgumentNullException(
                    nameof(hmacKey));

            string id =
                Convert.ToBase64String(
                    RandomNumberGenerator.GetBytes(32));

            var enrollment =
                new PendingTotpEnrollment
                {
                    Id = id,
                    Username = username,
                    HmacKey = hmacKey,
                    ExpiresAt =
                        DateTimeOffset.UtcNow.Add(lifetime)
                };

            lock (_sync)
            {
                _pending.Add(
                    id,
                    enrollment);
            }

            return id;
        }

        public bool TryGet(
            string id,
            out PendingTotpEnrollment? enrollment)
        {
            Console.WriteLine(
                $"SERVER: TryGet enrollment ID: {id}");

            lock (_sync)
            {
                Console.WriteLine(
                    $"SERVER: Pending enrollment count: {_pending.Count}");

                if (_pending.TryGetValue(
                        id,
                        out enrollment))
                {
                    Console.WriteLine(
                        "SERVER: Enrollment ID found.");

                    if (enrollment.ExpiresAt >
                        DateTime.UtcNow)
                    {
                        return true;
                    }

                    Console.WriteLine(
                        "SERVER: Enrollment expired.");

                    _pending.Remove(id);
                }
            }

            Console.WriteLine(
                "SERVER: Enrollment ID NOT found.");

            enrollment = null;

            return false;
        }

        public bool Remove(string id)
        {
            lock (_sync)
            {
                if (!_pending.Remove(
                        id,
                        out var enrollment))
                {
                    return false;
                }

                enrollment.HmacKey.Dispose();

                return true;
            }
        }
    }
}
