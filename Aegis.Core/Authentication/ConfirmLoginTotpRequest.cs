using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.Authentication
{
    internal sealed class ConfirmLoginTotpRequest
    {
        public string AuthenticationId { get; init; } = "";

        public string Code { get; init; } = "";
    }
}
