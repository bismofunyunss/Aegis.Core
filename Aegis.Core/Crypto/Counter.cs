using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto
{
    internal class Counter
    {
        internal static (byte[] state, ulong version) DecryptChain(
  byte[] cipher, byte[] nonce, byte[] tag, byte[] key)
        {
            byte[] plaintext = new byte[cipher.Length];

            byte[] slicedKey = new byte[key.Length / 2];
            Buffer.BlockCopy(key, 0, slicedKey, 0, 32);

            using var aes = new AesGcm(slicedKey, 16);
            aes.Decrypt(nonce, cipher, tag, plaintext);

            byte[] state = new byte[32];
            Buffer.BlockCopy(plaintext, 0, state, 0, 32);

            ulong version = BitConverter.ToUInt64(plaintext, 32);

            return (state, version);
        }

        internal static (byte[] cipher, byte[] nonce, byte[] tag) EncryptChain(
            byte[] state, ulong version, byte[] key)
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);

            byte[] slicedKey = new byte[key.Length / 2];
            Buffer.BlockCopy(key, 0, slicedKey, 0, 32);

            byte[] plaintext = new byte[40];
            Buffer.BlockCopy(state, 0, plaintext, 0, 32);
            Buffer.BlockCopy(BitConverter.GetBytes(version), 0, plaintext, 32, 8);

            byte[] cipher = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            using var aes = new AesGcm(slicedKey, 16);
            aes.Encrypt(nonce, plaintext, cipher, tag);

            return (cipher, nonce, tag);
        }
    }
}
