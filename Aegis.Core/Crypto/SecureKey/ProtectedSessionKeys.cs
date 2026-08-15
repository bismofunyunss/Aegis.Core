using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto.SecureKey
{
    internal sealed class ProtectedSessionKeys : IDisposable
    {
        // ============================================================
        // LIVE SESSION KEK
        //
        // Random AES-256 key.
        //
        // Stored through AesKek -> SecureBuffer.
        //
        // This exists only for the lifetime of the authenticated
        // application session.
        // ============================================================

        private AesKek? _kek;


        // ============================================================
        // TPM-PROTECTED SESSION KEK
        //
        // RSA-OAEP-SHA256 encrypted AES-256 KEK.
        //
        // This is ciphertext, not plaintext key material.
        //
        // RSA-2048 => 256 bytes.
        // ============================================================

        private byte[]? _wrappedKek;


        // ============================================================
        // AES-KW WRAPPED SESSION KEYS
        //
        // These contain encrypted versions of the actual key
        // material.
        // ============================================================

        private byte[]? _wrappedAccountRootKey;

        private byte[]? _wrappedFileRootKey;

        private byte[]? _wrappedMemoryProtectionKey;

        private byte[]? _wrappedIpcWrappingKey;

        private byte[]? _wrappedHmacKey;


        // ============================================================
        // FILE ROOT SALT
        //
        // Not secret.
        //
        // Required when reconstructing FileRootKey.
        // ============================================================

        private byte[]? _fileRootSalt;


        private bool _disposed;


        // ============================================================
        // PRIVATE CONSTRUCTOR
        // ============================================================

        private ProtectedSessionKeys(
            AesKek kek,
            byte[] wrappedKek,
            byte[] wrappedAccountRootKey,
            byte[] wrappedFileRootKey,
            byte[] wrappedMemoryProtectionKey,
            byte[] wrappedIpcWrappingKey,
            byte[] wrappedHmacKey,
            byte[] fileRootSalt)
        {
            _kek =
                kek
                ?? throw new ArgumentNullException(
                    nameof(kek));

            _wrappedKek =
                wrappedKek
                ?? throw new ArgumentNullException(
                    nameof(wrappedKek));

            _wrappedAccountRootKey =
                wrappedAccountRootKey
                ?? throw new ArgumentNullException(
                    nameof(wrappedAccountRootKey));

            _wrappedFileRootKey =
                wrappedFileRootKey
                ?? throw new ArgumentNullException(
                    nameof(wrappedFileRootKey));

            _wrappedMemoryProtectionKey =
                wrappedMemoryProtectionKey
                ?? throw new ArgumentNullException(
                    nameof(wrappedMemoryProtectionKey));

            _wrappedIpcWrappingKey =
                wrappedIpcWrappingKey
                ?? throw new ArgumentNullException(
                    nameof(wrappedIpcWrappingKey));

            _wrappedHmacKey =
                wrappedHmacKey
                ?? throw new ArgumentNullException(
                    nameof(wrappedHmacKey));

            _fileRootSalt =
                fileRootSalt
                ?? throw new ArgumentNullException(
                    nameof(fileRootSalt));
        }


        // ============================================================
        // CREATE
        //
        // Creates a new random AES-256 session KEK.
        //
        // The KEK is:
        //
        //     1. Protected by the TPM-backed RSA key.
        //     2. Used as the AES-KW KEK for all five session keys.
        //
        // The plaintext session KEK remains only inside AesKek.
        // ============================================================

        internal static ProtectedSessionKeys Create(
            TpmRsaKeyProtector tpm,
            AccountRootKey accountRootKey,
            FileRootKey fileRootKey,
            MemoryProtectionKey memoryProtectionKey,
            IpcWrappingKey ipcWrappingKey,
            HmacKey hmacKey)
        {
            ArgumentNullException.ThrowIfNull(
                tpm);

            ArgumentNullException.ThrowIfNull(
                accountRootKey);

            ArgumentNullException.ThrowIfNull(
                fileRootKey);

            ArgumentNullException.ThrowIfNull(
                memoryProtectionKey);

            ArgumentNullException.ThrowIfNull(
                ipcWrappingKey);

            ArgumentNullException.ThrowIfNull(
                hmacKey);


            AesKek? kek = null;

            byte[]? wrappedKek = null;

            byte[]? wrappedAccount = null;
            byte[]? wrappedFile = null;
            byte[]? wrappedMemory = null;
            byte[]? wrappedIpc = null;
            byte[]? wrappedHmac = null;

            byte[]? fileSalt = null;


            try
            {
                // ====================================================
                // CREATE RANDOM AES-256 SESSION KEK
                // ====================================================

                kek =
                    AesKek.Generate();


                // ====================================================
                // PROTECT SESSION KEK WITH TPM
                //
                // RSA-OAEP-SHA256
                //
                // Only the 32-byte KEK is sent through RSA.
                // ====================================================

                wrappedKek =
                    tpm.ProtectKek(
                        kek.Key);


                if (wrappedKek.Length == 0)
                {
                    throw new CryptographicException(
                        "TPM returned an empty wrapped KEK.");
                }


                // ====================================================
                // WRAP ACCOUNT ROOT KEY
                // ====================================================

                wrappedAccount =
                    KeyWrapper.Wrap(
                        kek,
                        accountRootKey.Key);


                // ====================================================
                // WRAP FILE ROOT KEY
                // ====================================================

                wrappedFile =
                    KeyWrapper.Wrap(
                        kek,
                        fileRootKey.Key);


                // ====================================================
                // WRAP MEMORY PROTECTION KEY
                // ====================================================

                wrappedMemory =
                    KeyWrapper.Wrap(
                        kek,
                        memoryProtectionKey.Key);


                // ====================================================
                // WRAP IPC WRAPPING KEY
                // ====================================================

                wrappedIpc =
                    KeyWrapper.Wrap(
                        kek,
                        ipcWrappingKey.Key);


                // ====================================================
                // WRAP HMAC KEY
                // ====================================================

                wrappedHmac =
                    KeyWrapper.Wrap(
                        kek,
                        hmacKey.Key);


                // ====================================================
                // COPY FILE ROOT SALT
                //
                // Public metadata; not secret.
                // ====================================================

                fileSalt =
                    fileRootKey.ExportSalt();


                // ====================================================
                // CREATE FINAL OBJECT
                // ====================================================

                var result =
                    new ProtectedSessionKeys(
                        kek,
                        wrappedKek,
                        wrappedAccount,
                        wrappedFile,
                        wrappedMemory,
                        wrappedIpc,
                        wrappedHmac,
                        fileSalt);


                // ====================================================
                // OWNERSHIP TRANSFER
                // ====================================================

                kek = null;

                wrappedKek = null;

                wrappedAccount = null;
                wrappedFile = null;
                wrappedMemory = null;
                wrappedIpc = null;
                wrappedHmac = null;

                fileSalt = null;


                return result;
            }
            catch
            {
                // ====================================================
                // SECURE CLEANUP
                // ====================================================

                kek?.Dispose();


                if (wrappedKek != null)
                {
                    CryptographicOperations.ZeroMemory(
                        wrappedKek);
                }


                if (wrappedAccount != null)
                {
                    CryptographicOperations.ZeroMemory(
                        wrappedAccount);
                }


                if (wrappedFile != null)
                {
                    CryptographicOperations.ZeroMemory(
                        wrappedFile);
                }


                if (wrappedMemory != null)
                {
                    CryptographicOperations.ZeroMemory(
                        wrappedMemory);
                }


                if (wrappedIpc != null)
                {
                    CryptographicOperations.ZeroMemory(
                        wrappedIpc);
                }


                if (wrappedHmac != null)
                {
                    CryptographicOperations.ZeroMemory(
                        wrappedHmac);
                }


                if (fileSalt != null)
                {
                    CryptographicOperations.ZeroMemory(
                        fileSalt);
                }


                throw;
            }
        }


        // ============================================================
        // CREATE FROM TPM-WRAPPED KEK
        //
        // This is useful if you later want to reconstruct the
        // ProtectedSessionKeys object from its encrypted representation
        // while the application is still running.
        //
        // TPM unwraps the AES KEK once.
        // ============================================================

        internal static ProtectedSessionKeys Open(
            TpmRsaKeyProtector tpm,
            byte[] wrappedKek,
            byte[] wrappedAccountRootKey,
            byte[] wrappedFileRootKey,
            byte[] wrappedMemoryProtectionKey,
            byte[] wrappedIpcWrappingKey,
            byte[] wrappedHmacKey,
            byte[] fileRootSalt)
        {
            ArgumentNullException.ThrowIfNull(
                tpm);

            ArgumentNullException.ThrowIfNull(
                wrappedKek);

            ArgumentNullException.ThrowIfNull(
                wrappedAccountRootKey);

            ArgumentNullException.ThrowIfNull(
                wrappedFileRootKey);

            ArgumentNullException.ThrowIfNull(
                wrappedMemoryProtectionKey);

            ArgumentNullException.ThrowIfNull(
                wrappedIpcWrappingKey);

            ArgumentNullException.ThrowIfNull(
                wrappedHmacKey);

            ArgumentNullException.ThrowIfNull(
                fileRootSalt);


            byte[]? plaintextKek = null;

            AesKek? kek = null;

            try
            {
                // ====================================================
                // TPM UNWRAP
                // ====================================================

                plaintextKek =
                    tpm.UnprotectKek(
                        wrappedKek);


                if (plaintextKek.Length != 32)
                {
                    throw new CryptographicException(
                        "Invalid AES session KEK length.");
                }


                kek =
                    new AesKek(
                        plaintextKek);


                // ====================================================
                // COPY ALL WRAPPED MATERIAL
                // ====================================================

                var result =
                    new ProtectedSessionKeys(
                        kek,
                        wrappedKek.ToArray(),
                        wrappedAccountRootKey.ToArray(),
                        wrappedFileRootKey.ToArray(),
                        wrappedMemoryProtectionKey.ToArray(),
                        wrappedIpcWrappingKey.ToArray(),
                        wrappedHmacKey.ToArray(),
                        fileRootSalt.ToArray());


                kek = null;

                return result;
            }
            catch
            {
                kek?.Dispose();

                throw;
            }
            finally
            {
                if (plaintextKek != null)
                {
                    CryptographicOperations.ZeroMemory(
                        plaintextKek);
                }
            }
        }


        // ============================================================
        // UNWRAP ACCOUNT ROOT KEY
        // ============================================================

        internal AccountRootKey UnwrapAccountRootKey()
        {
            ThrowIfDisposed();

            using SecureBuffer plaintext =
                KeyWrapper.Unwrap(
                    _kek!,
                    _wrappedAccountRootKey!);

            byte[] key =
                plaintext.ToArrayCopy();

            try
            {
                return new AccountRootKey(
                    key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    key);
            }
        }


        // ============================================================
        // UNWRAP FILE ROOT KEY
        // ============================================================

        internal FileRootKey UnwrapFileRootKey()
        {
            ThrowIfDisposed();

            using SecureBuffer plaintext =
                KeyWrapper.Unwrap(
                    _kek!,
                    _wrappedFileRootKey!);

            byte[] key =
                plaintext.ToArrayCopy();

            try
            {
                return new FileRootKey(
                    key,
                    _fileRootSalt!);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    key);
            }
        }


        // ============================================================
        // UNWRAP MEMORY PROTECTION KEY
        // ============================================================

        internal MemoryProtectionKey
            UnwrapMemoryProtectionKey()
        {
            ThrowIfDisposed();

            using SecureBuffer plaintext =
                KeyWrapper.Unwrap(
                    _kek!,
                    _wrappedMemoryProtectionKey!);

            byte[] key =
                plaintext.ToArrayCopy();

            try
            {
                return new MemoryProtectionKey(
                    key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    key);
            }
        }


        // ============================================================
        // UNWRAP IPC WRAPPING KEY
        // ============================================================

        internal IpcWrappingKey
            UnwrapIpcWrappingKey()
        {
            ThrowIfDisposed();

            using SecureBuffer plaintext =
                KeyWrapper.Unwrap(
                    _kek!,
                    _wrappedIpcWrappingKey!);

            byte[] key =
                plaintext.ToArrayCopy();

            try
            {
                return new IpcWrappingKey(
                    key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    key);
            }
        }


        // ============================================================
        // UNWRAP HMAC KEY
        // ============================================================

        internal HmacKey UnwrapHmacKey()
        {
            ThrowIfDisposed();

            using SecureBuffer plaintext =
                KeyWrapper.Unwrap(
                    _kek!,
                    _wrappedHmacKey!);

            byte[] key =
                plaintext.ToArrayCopy();

            try
            {
                return new HmacKey(
                    key);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(
                    key);
            }
        }


        // ============================================================
        // TPM-WRAPPED KEK EXPORT
        //
        // Useful if you need to store/transmit the protected
        // representation within the application's lifetime.
        //
        // This returns ciphertext, NOT the plaintext KEK.
        // ============================================================

        internal byte[] ExportWrappedKek()
        {
            ThrowIfDisposed();

            return _wrappedKek!
                .ToArray();
        }


        // ============================================================
        // EXPORT WRAPPED KEY MATERIAL
        //
        // These return ciphertext copies.
        // ============================================================

        internal byte[] ExportWrappedAccountRootKey()
        {
            ThrowIfDisposed();

            return _wrappedAccountRootKey!
                .ToArray();
        }


        internal byte[] ExportWrappedFileRootKey()
        {
            ThrowIfDisposed();

            return _wrappedFileRootKey!
                .ToArray();
        }


        internal byte[] ExportWrappedMemoryProtectionKey()
        {
            ThrowIfDisposed();

            return _wrappedMemoryProtectionKey!
                .ToArray();
        }


        internal byte[] ExportWrappedIpcWrappingKey()
        {
            ThrowIfDisposed();

            return _wrappedIpcWrappingKey!
                .ToArray();
        }


        internal byte[] ExportWrappedHmacKey()
        {
            ThrowIfDisposed();

            return _wrappedHmacKey!
                .ToArray();
        }


        // ============================================================
        // FILE ROOT SALT
        // ============================================================

        internal byte[] ExportFileRootSalt()
        {
            ThrowIfDisposed();

            return _fileRootSalt!
                .ToArray();
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


            // ========================================================
            // DESTROY PLAINTEXT SESSION KEK
            // ========================================================

            _kek?.Dispose();

            _kek = null;


            // ========================================================
            // DESTROY TPM-WRAPPED KEK
            // ========================================================

            if (_wrappedKek != null)
            {
                CryptographicOperations.ZeroMemory(
                    _wrappedKek);

                _wrappedKek = null;
            }


            // ========================================================
            // DESTROY WRAPPED KEY BLOBS
            // ========================================================

            if (_wrappedAccountRootKey != null)
            {
                CryptographicOperations.ZeroMemory(
                    _wrappedAccountRootKey);

                _wrappedAccountRootKey = null;
            }


            if (_wrappedFileRootKey != null)
            {
                CryptographicOperations.ZeroMemory(
                    _wrappedFileRootKey);

                _wrappedFileRootKey = null;
            }


            if (_wrappedMemoryProtectionKey != null)
            {
                CryptographicOperations.ZeroMemory(
                    _wrappedMemoryProtectionKey);

                _wrappedMemoryProtectionKey = null;
            }


            if (_wrappedIpcWrappingKey != null)
            {
                CryptographicOperations.ZeroMemory(
                    _wrappedIpcWrappingKey);

                _wrappedIpcWrappingKey = null;
            }


            if (_wrappedHmacKey != null)
            {
                CryptographicOperations.ZeroMemory(
                    _wrappedHmacKey);

                _wrappedHmacKey = null;
            }


            // ========================================================
            // DESTROY SALT COPY
            // ========================================================

            if (_fileRootSalt != null)
            {
                CryptographicOperations.ZeroMemory(
                    _fileRootSalt);

                _fileRootSalt = null;
            }


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
