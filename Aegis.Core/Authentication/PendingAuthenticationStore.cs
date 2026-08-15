using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Authentication
{
    internal sealed class PendingAuthenticationStore
    {
        private readonly object _sync = new();

        private readonly Dictionary<
            string,
            PendingAuthentication> _pending =
            new();


        public string Add(
            PendingAuthentication authentication)
        {
            if (authentication == null)
                throw new ArgumentNullException(
                    nameof(authentication));

            string id =
                Convert.ToBase64String(
                    RandomNumberGenerator.GetBytes(
                        32));

            lock (_sync)
            {
                _pending.Add(
                    id,
                    authentication);
            }

            return id;
        }


        public bool TryGet(
            string id,
            out PendingAuthentication? authentication)
        {
            lock (_sync)
            {
                if (_pending.TryGetValue(
                        id,
                        out authentication))
                {
                    if (!authentication.IsExpired)
                    {
                        return true;
                    }

                    _pending.Remove(id);
                }
            }

            authentication = null;

            return false;
        }


        public bool Remove(
            string id)
        {
            lock (_sync)
            {
                return _pending.Remove(id);
            }
        }
    }
}
