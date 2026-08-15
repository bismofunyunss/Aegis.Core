using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core.Crypto.SecureKey
{
    internal sealed class ProtectedSessionKeys : IDisposable
    {
        // ============================================================
        // SESSION KEK
        //
        // Random AES-256 key generated for this application session.
        //
        // It is held in SecureBuffer through AesKek.
        // ============================================================

        private AesKek? _kek;


        // ============================================================
        // WRAPPED KEY MATERIAL
        //
        // These are ciphertext/wrapped representations.
        //
        // They are NOT plaintext keys.
        // ============================================================

        private byte[]? _wrappedAccountRootKey;

        private byte[]? _wrappedFileRootKey;

        private byte[]? _wrappedMemoryProtectionKey;

        private byte[]? _wrappedIpcWrappingKey;

        private byte[]? _wrappedHmacKey;


        // ============================================================
        // FILE ROOT KEY METADATA
        //
        // The salt is not secret, so it does not need encryption.
        //
        // It is required to reconstruct FileRootKey because
        // FileRootKey contains both the key material and its salt.
        // ============================================================

        private byte[]? _fileRootSalt;


        private bool _disposed;


        // ============================================================
        // PRIVATE CONSTRUCTOR
        // ============================================================

        private ProtectedSessionKeys(
            AesKek kek,
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
        // Takes the existing typed key objects and immediately wraps
        // their underlying SecureBuffer material.
        //
        // After this method returns, this object contains ONLY:
        //
        //     AES KEK
        //     wrapped AccountRootKey
        //     wrapped FileRootKey
        //     wrapped MemoryProtectionKey
        //     wrapped IpcWrappingKey
        //     wrapped HmacKey
        //     FileRoot salt
        //
        // It does NOT retain references to the original key objects.
        // ============================================================

        internal static ProtectedSessionKeys Create(
            AccountRootKey accountRootKey,
            FileRootKey fileRootKey,
            MemoryProtectionKey memoryProtectionKey,
            IpcWrappingKey ipcWrappingKey,
            HmacKey hmacKey)
        {
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

            byte[]? wrappedAccount = null;
            byte[]? wrappedFile = null;
            byte[]? wrappedMemory = null;
            byte[]? wrappedIpc = null;
            byte[]? wrappedHmac = null;
            byte[]? fileSalt = null;


            try
            {
                // ====================================================
                // GENERATE NEW RANDOM SESSION KEK
                // ====================================================

                kek =
                    AesKek.Generate();


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
                // Salt is metadata, not secret key material.
                // ====================================================

                fileSalt =
                    fileRootKey.ExportSalt();


                // ====================================================
                // TRANSFER OWNERSHIP
                // ====================================================

                ProtectedSessionKeys result =
                    new ProtectedSessionKeys(
                        kek,
                        wrappedAccount,
                        wrappedFile,
                        wrappedMemory,
                        wrappedIpc,
                        wrappedHmac,
                        fileSalt);


                // Prevent cleanup below from destroying the data
                // now owned by result.
                kek = null;

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
                kek?.Dispose();

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
        // UNWRAP ACCOUNT ROOT KEY
        //
        // Creates a temporary plaintext AccountRootKey.
        //
        // The caller OWNS the returned object and must Dispose() it.
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
        //
        // FileRootKey additionally requires its salt.
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
            // DESTROY SESSION KEK
            // ========================================================

            _kek?.Dispose();

            _kek = null;


            // ========================================================
            // DESTROY WRAPPED KEY BLOBS
            //
            // They're not plaintext, but there's no reason to retain
            // them after the session has ended.
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
            // DESTROY METADATA COPY
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
