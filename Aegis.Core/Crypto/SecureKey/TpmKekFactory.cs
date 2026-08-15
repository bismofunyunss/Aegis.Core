using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto.SecureKey
{
    internal static class TpmKekFactory
    {
        // ============================================================
        // CREATE A NEW RANDOM AES-256 KEK AND PROTECT IT WITH TPM
        // ============================================================

        internal static TpmProtectedKek Create(
            TpmRsaKeyProtector tpm)
        {
            ArgumentNullException.ThrowIfNull(
                tpm);

            byte[] kek =
                RandomNumberGenerator.GetBytes(32);

            try
            {
                byte[] wrapped =
                    tpm.ProtectKek(
                        kek);

                try
                {
                    return new TpmProtectedKek(
                        wrapped);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(
                        wrapped);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    kek);
            }
        }


        // ============================================================
        // UNWRAP KEK USING TPM
        //
        // The returned AesKek immediately places the plaintext key
        // inside SecureBuffer.
        // ============================================================

        internal static AesKek Unprotect(
            TpmRsaKeyProtector tpm,
            TpmProtectedKek protectedKek)
        {
            ArgumentNullException.ThrowIfNull(
                tpm);

            ArgumentNullException.ThrowIfNull(
                protectedKek);

            byte[] wrapped =
                protectedKek.Export();

            byte[]? kek = null;

            try
            {
                kek =
                    tpm.UnprotectKek(
                        wrapped);

                if (kek.Length != 32)
                {
                    throw new CryptographicException(
                        "TPM returned an invalid KEK length.");
                }

                return new AesKek(
                    kek);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    wrapped);

                if (kek != null)
                {
                    CryptographicOperations.ZeroMemory(
                        kek);
                }
            }
        }
    }
}
