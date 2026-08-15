using Aegis.Contracts;
using Aegis.Core.Crypto;
using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.Authentication
{
    internal class RegistrationResult
    {
        public required KeyBlob Blob { get; init; }

        public required HmacKey HmacKey { get; init; }
    }
}
