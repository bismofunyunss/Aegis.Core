using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Aegis.Contracts;
using Konscious.Security.Cryptography;

namespace Aegis.Core.Crypto
{
    internal static class PasswordDerivation
    {
        public static async Task<byte[]> Argon2Id(
            byte[] password,
            byte[] salt,
            int outputSize,
            CryptoSettings settings)
        {
            if (password == null || password.Length == 0)
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            if (salt == null || salt.Length == 0)
                throw new ArgumentException("Salt cannot be null or empty.", nameof(salt));

            if (settings == null)
                throw new ArgumentNullException(nameof(settings));

            using var argon2 = new Argon2id(password)
            {
                Salt = salt,
                DegreeOfParallelism = settings.ArgonParallelism,
                Iterations = settings.ArgonIterations,
                MemorySize = settings.ArgonMemoryKb
            };

            var result = await argon2
                .GetBytesAsync(outputSize)
                .ConfigureAwait(false);

            return result;
        }

        public static async Task<byte[]> Pbkdf2Async(
            byte[] password,
            byte[] salt,
            int outputSize,
            CryptoSettings settings)
        {
            if (password == null || password.Length == 0)
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            if (salt == null || salt.Length == 0)
                throw new ArgumentException("Salt cannot be null or empty.", nameof(salt));

            if (settings == null)
                throw new ArgumentNullException(nameof(settings));

            return await Task.Run(() =>
            {
                using var pbkdf2 = new Rfc2898DeriveBytes(
                    password,
                    salt,
                    settings.Pbkdf2Iterations,
                    HashAlgorithmName.SHA256);

                return pbkdf2.GetBytes(outputSize);
            }).ConfigureAwait(false);
        }
    }
}
