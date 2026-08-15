using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Text;

namespace Aegis.Core.Crypto
{
    internal static class KeyWrap
    {
        /// <summary>
        ///     AES Key Wrap (RFC 5649) wrapper.
        /// </summary>
        public static byte[] AesKeyWrap(byte[] kek, byte[] keyToWrap)
        {
            var engine = new AesWrapPadEngine(); // RFC 5649
            engine.Init(true, new KeyParameter(kek)); // true = wrap
            return engine.Wrap(keyToWrap, 0, keyToWrap.Length);
        }

        /// <summary>
        ///     AES Key Unwrap (RFC 5649) unwrapper.
        /// </summary>
        public static byte[] AesKeyUnwrap(byte[] kek, byte[] wrappedKey)
        {
            var engine = new AesWrapPadEngine(); // RFC 5649
            engine.Init(false, new KeyParameter(kek)); // false = unwrap
            return engine.Unwrap(wrappedKey, 0, wrappedKey.Length);
        }
    }
}
