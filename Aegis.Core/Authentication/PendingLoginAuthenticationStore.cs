using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Authentication
{
    internal sealed class PendingLoginAuthenticationStore
    {
        private readonly object _sync = new();

        private readonly Dictionary<
            string,
            PendingLoginAuthentication> _pending =
            new();

        public string Add(
            PendingLoginAuthentication authentication)
        {
            if (authentication == null)
                throw new ArgumentNullException(
                    nameof(authentication));

            string id =
                Convert.ToBase64String(
                    RandomNumberGenerator.GetBytes(32));

            lock (_sync)
            {
                _pending.Add(
                    id,
                    authentication);
            }

            return id;
        }

        public bool Take(
            string id,
            out PendingLoginAuthentication? authentication)
        {
            lock (_sync)
            {
                if (!_pending.TryGetValue(
                        id,
                        out authentication))
                {
                    authentication = null;
                    return false;
                }

                _pending.Remove(id);

                return true;
            }
        }

        public bool RemoveWithoutDisposing(
            string id)
        {
            lock (_sync)
            {
                return _pending.Remove(id);
            }
        }

        public bool TryGet(
            string id,
            out PendingLoginAuthentication? authentication)
        {
            lock (_sync)
            {
                if (!_pending.TryGetValue(
                        id,
                        out authentication))
                {
                    authentication = null;
                    return false;
                }

                if (!authentication.IsExpired)
                {
                    return true;
                }

                _pending.Remove(id);

                authentication.Dispose();

                authentication = null;

                return false;
            }
        }

        public bool Remove(
            string id)
        {
            lock (_sync)
            {
                if (!_pending.TryGetValue(
                        id,
                        out var authentication))
                {
                    return false;
                }

                _pending.Remove(id);

                authentication.Dispose();

                return true;
            }
        }

        public bool Transfer(
            string id,
            out PendingLoginAuthentication? authentication)
        {
            lock (_sync)
            {
                if (!_pending.TryGetValue(
                        id,
                        out authentication))
                {
                    authentication = null;
                    return false;
                }

                _pending.Remove(id);

                // Ownership is transferred to the caller.
                // Do NOT dispose the authentication here.

                return true;
            }
        }
    }
}
