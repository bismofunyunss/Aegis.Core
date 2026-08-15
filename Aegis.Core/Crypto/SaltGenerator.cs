using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto
{
    public sealed class SaltGenerator
    {
        // Generate salts for keys and hmac keys
        internal static byte[][] CreateSalts(int saltLength = 128)
        {
            byte[][] salts = new byte[9][];

            for (int i = 0; i < 9; i++)
            {
                salts[i] = RandomNumberGenerator.GetBytes(saltLength);
            }

            return salts;
        }
    }
}
