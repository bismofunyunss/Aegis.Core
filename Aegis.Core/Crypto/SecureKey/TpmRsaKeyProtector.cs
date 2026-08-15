using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto.SecureKey
{
    internal sealed class TpmRsaKeyProtector : IDisposable
    {
        private readonly CngKey _cngKey;
        private readonly RSACng _rsa;

        private bool _disposed;

        private const string KeyName =
            "AEGIS-SESSION-KEY-PROTECTOR";


        // ============================================================
        // CREATE / OPEN TPM KEY
        // ============================================================

        private TpmRsaKeyProtector(
            CngKey cngKey)
        {
            _cngKey =
                cngKey
                ?? throw new ArgumentNullException(
                    nameof(cngKey));

            try
            {
                _rsa =
                    new RSACng(
                        _cngKey);

            }
            catch
            {
                _cngKey.Dispose();

                throw;
            }
        }


        // ============================================================
        // OPEN EXISTING TPM KEY OR CREATE IT
        // ============================================================

        public static TpmRsaKeyProtector OpenOrCreate()
        {
            CngKey? key = null;

            try
            {
                if (CngKey.Exists(
                    KeyName,
                    CngProvider.MicrosoftPlatformCryptoProvider))
                {
                    key =
                        CngKey.Open(
                            KeyName,
                            CngProvider.MicrosoftPlatformCryptoProvider);
                }
                else
                {
                    var parameters =
                        new CngKeyCreationParameters
                        {
                            Provider =
                                CngProvider.MicrosoftPlatformCryptoProvider,

                            KeyUsage =
                                CngKeyUsages.Decryption,

                            KeyCreationOptions =
                                CngKeyCreationOptions.None,

                            ExportPolicy = CngExportPolicies.None
                        };

                    key =
                        CngKey.Create(
                            CngAlgorithm.Rsa,
                            KeyName,
                            parameters);
                }

                return new TpmRsaKeyProtector(
                    key);
            }
            catch
            {
                key?.Dispose();

                throw;
            }
        }


        // ============================================================
        // PROTECT AES KEK
        //
        // RSA is ONLY used for the small 32-byte KEK.
        //
        // RSA-OAEP-SHA256
        // ============================================================

        public byte[] ProtectKek(
            ReadOnlySpan<byte> kek)
        {
            ThrowIfDisposed();

            if (kek.Length != 32)
            {
                throw new ArgumentException(
                    "KEK must be exactly 32 bytes.",
                    nameof(kek));
            }

            return _rsa.Encrypt(
                kek.ToArray(),
                RSAEncryptionPadding.OaepSHA256);
        }


        // ============================================================
        // UNPROTECT AES KEK
        //
        // The RSA private operation is performed through the
        // Microsoft Platform Crypto Provider / TPM.
        // ============================================================

        public byte[] UnprotectKek(
            ReadOnlySpan<byte> protectedKek)
        {
            ThrowIfDisposed();

            if (protectedKek.Length == 0)
            {
                throw new ArgumentException(
                    "Protected KEK cannot be empty.",
                    nameof(protectedKek));
            }

            return _rsa.Decrypt(
                protectedKek.ToArray(),
                RSAEncryptionPadding.OaepSHA256);
        }


        // ============================================================
        // EXPORT PUBLIC KEY
        //
        // Useful if another component needs to encrypt a KEK
        // without possessing the TPM private key.
        // ============================================================

        public byte[] ExportPublicKey()
        {
            ThrowIfDisposed();

            return _rsa.ExportSubjectPublicKeyInfo();
        }


        // ============================================================
        // DISPOSE
        // ============================================================

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            _rsa.Dispose();
            _cngKey.Dispose();

            GC.SuppressFinalize(
                this);
        }


        // ============================================================
        // DISPOSE CHECK
        // ============================================================

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(
                _disposed,
                this);
        }
    }
}
